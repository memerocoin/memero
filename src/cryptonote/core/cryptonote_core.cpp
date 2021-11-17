
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "cryptonote_core.h"

#include "cryptonote/functional/helper.hpp"
#include "cryptonote/tx/functional/tx_check.h"

#include "math/ringct/pseudo_functional/rctSigs.hpp"

#include "tools/common/notify.h"
#include "tools/common/threadpool.h"

#include <boost/uuid/nil_generator.hpp>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "cn"

#define LOG_ERROR_VER(x) LOG_CATEGORY_ERROR("verify", x)

#define BAD_SEMANTICS_TXES_MAX_SIZE 100

// basically at least how many bytes the block itself serializes to without the miner tx
#define BLOCK_SIZE_SANITY_LEEWAY 100

using namespace constant;

namespace cryptonote
{
  const command_line::arg_descriptor<bool, false> arg_testnet_on  = {
    "testnet"
  , "Run on testnet. The wallet must be launched with --testnet flag."
  , false
  };
  const command_line::arg_descriptor<diff_t> arg_fixed_difficulty  = {
    "fixed-difficulty"
  , "Fixed difficulty used for testing."
  , 0
  };
  const command_line::arg_descriptor<std::string, false, true> arg_data_dir = {
    "data-dir"
  , "Specify data directory"
  , tools::get_default_data_dir()
  , arg_testnet_on
  , [](bool testnet, bool defaulted, std::string val)->std::string {
      if (testnet && defaulted)
        return (std::filesystem::path(val) / "testnet").string();
      return val;
    }
  };
  const command_line::arg_descriptor<bool> arg_offline = {
    "offline"
  , "Do not listen for peers, nor connect to any"
  };
  static const command_line::arg_descriptor<std::string> arg_block_notify = {
    "block-notify"
  , "Run a program for each new block. "
    "%s = block hash."
  , ""
  };
  static const command_line::arg_descriptor<std::string> arg_reorg_notify = {
    "reorg-notify"
  , "Run a program for each new reorg. "
    "%s = split height, "
    "%h = blockchain height, "
    "%n = new blocks, "
    "%d = blocks discarded."
  , ""
  };
  static const command_line::arg_descriptor<std::string> arg_block_rate_notify = {
    "block-rate-notify"
  , "Run a program when the block rate undergoes large fluctuations. "
    "%t = minutes for the observation window, "
    "%b = blocks observed, "
    "%e = blocks expected."
  , ""
  };
  //-----------------------------------------------------------------------------------------------
  core::core(i_cryptonote_protocol* pprotocol):
              m_mempool(m_blockchain_storage),
              m_blockchain_storage(m_mempool),
              m_miner(this, [](const cryptonote::block &b, crypto::hash &hash) {
                hash = cryptonote::get_mining_hash(b);
                return true;
              }),
              m_starter_message_showed(false),
              m_target_blockchain_height(0),
              m_fluffy_blocks_enabled(true),
              m_nettype(UNDEFINED)
  {
    set_cryptonote_protocol(pprotocol);
  }
  void core::set_cryptonote_protocol(i_cryptonote_protocol* pprotocol)
  {
    if(pprotocol)
      m_pprotocol = pprotocol;
    else
      m_pprotocol = &m_protocol_stub;
  }

  //-----------------------------------------------------------------------------------
  void core::stop()
  {
    m_miner.stop();
    m_blockchain_storage.cancel();
  }
  //-----------------------------------------------------------------------------------
  void core::init_options(boost::program_options::options_description& desc)
  {
    command_line::add_arg(desc, arg_data_dir);

    command_line::add_arg(desc, arg_testnet_on);
    command_line::add_arg(desc, arg_fixed_difficulty);
    command_line::add_arg(desc, arg_offline);
    command_line::add_arg(desc, arg_block_notify);
    command_line::add_arg(desc, arg_reorg_notify);
    command_line::add_arg(desc, arg_block_rate_notify);

    miner::init_options(desc);
    BlockchainDB::init_options(desc);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_command_line(const boost::program_options::variables_map& vm)
  {
    if (m_nettype != FAKECHAIN)
    {
      const bool testnet = command_line::get_arg(vm, arg_testnet_on);
      m_nettype = testnet ? TESTNET : MAINNET;
    }

    m_config_folder = command_line::get_arg(vm, arg_data_dir);

    auto data_dir = std::filesystem::path(m_config_folder);

    m_offline = get_arg(vm, arg_offline);

    return true;
  }
  //-----------------------------------------------------------------------------------------------
  uint64_t core::get_current_blockchain_height() const
  {
    return m_blockchain_storage.get_current_blockchain_height();
  }
  //-----------------------------------------------------------------------------------------------
  void core::get_blockchain_top(uint64_t& height, crypto::hash& top_id) const
  {
    top_id = m_blockchain_storage.get_tail_id(height);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_blocks(uint64_t start_offset, size_t count, std::vector<std::pair<cryptonote::string_blob,block>>& blocks, std::vector<cryptonote::string_blob>& txs) const
  {
    return m_blockchain_storage.get_blocks(start_offset, count, blocks, txs);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_blocks(uint64_t start_offset, size_t count, std::vector<std::pair<cryptonote::string_blob,block>>& blocks) const
  {
    return m_blockchain_storage.get_blocks(start_offset, count, blocks);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_blocks(uint64_t start_offset, size_t count, std::vector<block>& blocks) const
  {
    std::vector<std::pair<cryptonote::string_blob, cryptonote::block>> bs;
    if (!m_blockchain_storage.get_blocks(start_offset, count, bs))
      return false;
    for (const auto &b: bs)
      blocks.push_back(b.second);
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_transactions_blobs(const std::span<const crypto::hash> txs_ids, std::vector<cryptonote::string_blob>& txs, std::vector<crypto::hash>& missed_txs) const
  {
    return m_blockchain_storage.get_transactions_blobs(txs_ids, txs, missed_txs);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_split_transactions_blobs(const std::span<const crypto::hash> txs_ids, std::vector<std::pair<crypto::hash, cryptonote::string_blob>>& txs, std::vector<crypto::hash>& missed_txs) const
  {
    return m_blockchain_storage.get_split_transactions_blobs(txs_ids, txs, missed_txs);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_transactions(const std::span<const crypto::hash> txs_ids, std::vector<transaction>& txs, std::vector<crypto::hash>& missed_txs) const
  {
    return m_blockchain_storage.get_transactions(txs_ids, txs, missed_txs);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_alternative_blocks(std::vector<block>& blocks) const
  {
    return m_blockchain_storage.get_alternative_blocks(blocks);
  }
  //-----------------------------------------------------------------------------------------------
  size_t core::get_alternative_blocks_count() const
  {
    return m_blockchain_storage.get_alternative_blocks_count();
  }
  //-----------------------------------------------------------------------------------------------
  bool core::init(const boost::program_options::variables_map& vm)
  {
    start_time = std::time(nullptr);

    const bool regtest = false;
    if (regtest)
    {
      m_nettype = FAKECHAIN;
    }
    bool r = handle_command_line(vm);
    LOG_ERROR_AND_RETURN_UNLESS(r, false, "Failed to handle command line");

    bool keep_alt_blocks = false;

    std::filesystem::path folder(m_config_folder);
    if (m_nettype == FAKECHAIN)
      folder /= "fake";

    // make sure the data directory exists, and try to lock it
    LOG_ERROR_AND_RETURN_UNLESS (std::filesystem::exists(folder) || std::filesystem::create_directories(folder), false,
      std::string("Failed to create directory ").append(folder.string()).c_str());

    // check for blockchain.bin
    try
    {
      const std::filesystem::path old_files = folder;
      if (std::filesystem::exists(old_files / "blockchain.bin"))
      {
        LOG_WARNING("Found old-style blockchain.bin in " << old_files.string());
        LOG_WARNING("Lolnero now uses a new format. You can either remove blockchain.bin to start syncing");
        LOG_WARNING("the blockchain anew, or use lolnero-blockchain-export and lolnero-blockchain-import to");
        LOG_WARNING("convert your existing blockchain.bin to the new format. See README.md for instructions.");
        return false;
      }
    }
    // folder might not be a directory, etc, etc
    catch (...) { }

    std::unique_ptr<BlockchainDB> db = new_db();
    if (!db)
    {
      LOG_ERROR("Failed to initialize a database");
      return false;
    }

    folder /= db->get_db_name();
    LOG_GLOBAL_INFO("Loading blockchain from folder " << folder.string() << " ...");

    const std::string filename = folder.string();
    // default to fast:async:1 if overridden
    blockchain_db_sync_mode sync_mode = db_defaultsync;
    bool sync_on_blocks = true;
    uint64_t sync_threshold = 1;

    if (m_nettype == FAKECHAIN)
    {
      // reset the db by removing the database file before opening it
      if (!db->remove_data_file(filename))
      {
        LOG_ERROR("Failed to remove data file in " << filename);
        return false;
      }
    }

    try
    {
      uint64_t db_flags = 0;

      db_flags = DBF_SAFE;
      sync_mode = db_async;

      db->open(filename, db_flags);
      if(!db->m_open)
        return false;
    }
    catch (const DB_ERROR& e)
    {
      LOG_ERROR("Error opening database: " << e.what());
      return false;
    }

    m_blockchain_storage.set_user_options(sync_on_blocks, sync_threshold, sync_mode);

    try
    {
      if (!command_line::is_arg_defaulted(vm, arg_block_notify))
      {
        struct hash_notify
        {
          tools::Notify cmdline;

          void operator()(const uint64_t, const std::vector<block> blocks) const
          {
            std::for_each(blocks.begin(), blocks.end(), [this](const auto& bl) {
              cmdline.notify("%s", epee::string_tools::pod_to_hex(get_block_hash(bl)).c_str(), NULL);
            });
          }
        };

        m_blockchain_storage.add_block_notify(hash_notify{{command_line::get_arg(vm, arg_block_notify).c_str()}});
      }
    }
    catch (const std::exception &e)
    {
      LOG_ERROR("Failed to parse block notify spec: " << e.what());
    }

    try
    {
      if (!command_line::is_arg_defaulted(vm, arg_reorg_notify))
        m_blockchain_storage.set_reorg_notify(std::shared_ptr<tools::Notify>(new tools::Notify(command_line::get_arg(vm, arg_reorg_notify).c_str())));
    }
    catch (const std::exception &e)
    {
      LOG_ERROR("Failed to parse reorg notify spec: " << e.what());
    }

    try
    {
      if (!command_line::is_arg_defaulted(vm, arg_block_rate_notify))
        m_block_rate_notify.reset(new tools::Notify(command_line::get_arg(vm, arg_block_rate_notify).c_str()));
    }
    catch (const std::exception &e)
    {
      LOG_ERROR("Failed to parse block rate notify spec: " << e.what());
    }

    const diff_t fixed_difficulty = command_line::get_arg(vm, arg_fixed_difficulty);
    r = m_blockchain_storage.init(db.release(), m_nettype, m_offline, fixed_difficulty);
    LOG_ERROR_AND_RETURN_UNLESS(r, false, "Failed to initialize blockchain storage");

    r = m_mempool.init();
    LOG_ERROR_AND_RETURN_UNLESS(r, false, "Failed to initialize memory pool");

    // now that we have a valid m_blockchain_storage, we can clean out any
    // transactions in the pool that do not conform to the current fork
    m_mempool.validate();

    bool show_time_stats = false;
    m_blockchain_storage.set_show_time_stats(show_time_stats);
    LOG_ERROR_AND_RETURN_UNLESS(r, false, "Failed to initialize blockchain storage");

    r = m_miner.init(vm, m_nettype);
    LOG_ERROR_AND_RETURN_UNLESS(r, false, "Failed to initialize miner instance");

    if (!keep_alt_blocks && !m_blockchain_storage.get_db().is_read_only())
      m_blockchain_storage.get_db().drop_alt_blocks();

    return load_state_data();
  }
  //-----------------------------------------------------------------------------------------------
  bool core::set_genesis_block(const block& b)
  {
    return m_blockchain_storage.reset_and_set_genesis_block(b);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::load_state_data()
  {
    // may be some code later
    return true;
  }
  //-----------------------------------------------------------------------------------------------
    bool core::deinit()
  {
    m_miner.stop();
    m_mempool.deinit();
    m_blockchain_storage.deinit();
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_incoming_tx_pre(const tx_blob_entry& tx_blob, tx_verification_context& tvc, cryptonote::transaction &tx, crypto::hash &tx_hash)
  {
    tvc = {};

    if(tx_blob.blob.size() > get_max_tx_size())
    {
      LOG_PRINT_L1("WRONG TRANSACTION BLOB, too big size " << tx_blob.blob.size() << ", rejected");
      tvc.m_verifivation_failed = true;
      tvc.m_too_big = true;
      return false;
    }

    tx_hash = crypto::null_hash;

    bool r = false;
    if (tx_blob.prunable_hash == crypto::null_hash)
    {
      r = parse_tx_from_blob(tx, tx_hash, tx_blob.blob);
    }

    if (!r)
    {
      LOG_PRINT_L1("WRONG TRANSACTION BLOB, Failed to parse, rejected");
      tvc.m_verifivation_failed = true;
      return false;
    }
    //std::cout << "!"<< tx.vin.size() << std::endl;

    bad_semantics_txes_lock.lock();
    for (int idx = 0; idx < 2; ++idx)
    {
      if (bad_semantics_txes[idx].find(tx_hash) != bad_semantics_txes[idx].end())
      {
        bad_semantics_txes_lock.unlock();
        LOG_PRINT_L1("Transaction already seen with bad semantics, rejected");
        tvc.m_verifivation_failed = true;
        return false;
      }
    }
    bad_semantics_txes_lock.unlock();

    const size_t max_tx_version = 2;
    if (tx.version == 0 || tx.version > max_tx_version)
    {
      // v2 is the latest one we know
      LOG_ERROR_VER("Bad tx version (" << tx.version << ", max is " << max_tx_version << ")");
      tvc.m_verifivation_failed = true;
      return false;
    }

    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_incoming_tx_post(const tx_blob_entry& tx_blob, tx_verification_context& tvc, cryptonote::transaction &tx, crypto::hash &tx_hash)
  {
    if(!check_tx_syntax(tx))
    {
      LOG_PRINT_L1("WRONG TRANSACTION BLOB, Failed to check tx " << tx_hash << " syntax, rejected");
      tvc.m_verifivation_failed = true;
      return false;
    }

    return true;
  }
  //-----------------------------------------------------------------------------------------------
  void core::set_semantics_failed(const crypto::hash &tx_hash)
  {
    LOG_PRINT_L1("WRONG TRANSACTION BLOB, Failed to check tx " << tx_hash << " semantic, rejected");
    bad_semantics_txes_lock.lock();
    bad_semantics_txes[0].insert(tx_hash);
    if (bad_semantics_txes[0].size() >= BAD_SEMANTICS_TXES_MAX_SIZE)
    {
      std::swap(bad_semantics_txes[0], bad_semantics_txes[1]);
      bad_semantics_txes[0].clear();
    }
    bad_semantics_txes_lock.unlock();
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_incoming_txs_span(const std::vector<tx_blob_entry> tx_blobs, std::span<tx_verification_context> tvc, relay_method tx_relay, bool relayed)
  {
    TRY_ENTRY();

    if (tx_blobs.size() != tvc.size())
    {
      LOG_ERROR("tx_blobs and tx_verification_context spans must have equal size");
      return false;
    }

    std::vector<txpool_event> results(tx_blobs.size());

    LOCK_RECURSIVE_MUTEX(m_incoming_tx_lock);

    tools::threadpool& tpool = tools::threadpool::getInstance();
    tools::threadpool::waiter waiter(tpool);
    auto it = tx_blobs.begin();
    for (size_t i = 0; i < tx_blobs.size(); i++, ++it) {
      tpool.submit(&waiter, [&, i, it] {
        try
        {
          results[i].res = handle_incoming_tx_pre(*it, tvc[i], results[i].tx, results[i].hash);
        }
        catch (const std::exception &e)
        {
          LOG_ERROR_VER("Exception in handle_incoming_tx_pre: " << e.what());
          tvc[i].m_verifivation_failed = true;
          results[i].res = false;
        }
      });
    }
    if (!waiter.wait())
      return false;
    it = tx_blobs.begin();
    std::vector<bool> already_have(tx_blobs.size(), false);
    for (size_t i = 0; i < tx_blobs.size(); i++, ++it) {
      if (!results[i].res)
        continue;
      if(m_mempool.have_tx(results[i].hash, relay_category::legacy))
      {
        LOG_PRINT_L2("tx " << results[i].hash << "already have transaction in tx_pool");
        already_have[i] = true;
      }
      else if(m_blockchain_storage.have_tx(results[i].hash))
      {
        LOG_PRINT_L2("tx " << results[i].hash << " already have transaction in blockchain");
        already_have[i] = true;
      }
      else
      {
        tpool.submit(&waiter, [&, i, it] {
          try
          {
            results[i].res = handle_incoming_tx_post(*it, tvc[i], results[i].tx, results[i].hash);
          }
          catch (const std::exception &e)
          {
            LOG_ERROR_VER("Exception in handle_incoming_tx_post: " << e.what());
            tvc[i].m_verifivation_failed = true;
            results[i].res = false;
          }
        });
      }
    }
    if (!waiter.wait())
      return false;

    std::vector<tx_verification_batch_info> tx_info;
    tx_info.reserve(tx_blobs.size());
    for (size_t i = 0; i < tx_blobs.size(); i++) {
      if (!results[i].res || already_have[i])
        continue;
      tx_info.push_back({&results[i].tx, results[i].hash, tvc[i], results[i].res});
    }
    if (!tx_info.empty())
      handle_incoming_tx_accumulated_batch(tx_info, tx_relay == relay_method::block);

    bool ok = true;
    it = tx_blobs.begin();
    for (size_t i = 0; i < tx_blobs.size(); i++, ++it) {
      if (!results[i].res)
      {
        ok = false;
        continue;
      }
      if (tx_relay == relay_method::block)
        get_blockchain_storage().on_new_tx_from_block(results[i].tx);
      if (already_have[i])
        continue;

      const uint64_t weight = it->blob.size();
      ok &= add_new_tx(results[i].tx, results[i].hash, tx_blobs[i].blob, weight, tvc[i], tx_relay, relayed);

      if(tvc[i].m_verifivation_failed)
      {LOG_ERROR_VER("Transaction verification failed: " << results[i].hash);}
      else if(tvc[i].m_verifivation_impossible)
      {LOG_ERROR_VER("Transaction verification impossible: " << results[i].hash);}

      if(tvc[i].m_added_to_pool)
      {
        LOG_DEBUG("tx added: " << results[i].hash);
      }
      else
        results[i].res = false;
    }

    return ok;
    CATCH_ENTRY_L0("core::handle_incoming_txs()", false);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_incoming_tx(const tx_blob_entry tx_blob, tx_verification_context& tvc, relay_method tx_relay, bool relayed)
  {
    std::vector<tx_verification_context> tvcV{tvc};
    const bool r = handle_incoming_txs(std::vector{tx_blob}, tvcV, tx_relay, relayed);
    tvc = tvcV[0];
    return r;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_tx_semantic(const transaction& tx, bool keeped_by_block) const
  {
    if(!tx.vin.size())
    {
      LOG_ERROR_VER("tx with empty inputs, rejected for tx id= " << get_transaction_hash(tx));
      return false;
    }

    if(!check_inputs_types_supported(tx))
    {
      LOG_ERROR_VER("unsupported input types for tx id= " << get_transaction_hash(tx));
      return false;
    }

    if(!check_outs_valid(tx))
    {
      LOG_ERROR_VER("tx with invalid outputs, rejected for tx id= " << get_transaction_hash(tx));
      return false;
    }
    if (tx.version > 1)
    {
      if (tx.ringct.output_commits.size() != tx.vout.size())
      {
        LOG_ERROR_VER("tx with mismatched vout/output_commits count, rejected for tx id= " << get_transaction_hash(tx));
        return false;
      }
    }

    if(!check_money_overflow(tx))
    {
      LOG_ERROR_VER("tx has money overflow, rejected for tx id= " << get_transaction_hash(tx));
      return false;
    }

    if (tx.version == 1)
    {
      LOG_ERROR_VER("pre rct txs should not exist");
    }
    // for version > 1, ringct signatures check verifies amounts match

    uint64_t tx_weight_limit = get_max_tx_size() - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
    if(!keeped_by_block && get_transaction_weight(tx) >= tx_weight_limit)
    {
      LOG_ERROR_VER("tx is too large " << get_transaction_weight(tx) << ", expected not bigger than " << tx_weight_limit);
      return false;
    }

    //check if tx use different key images
    if(!check_tx_inputs_keyimages_diff(tx))
    {
      LOG_ERROR_VER("tx uses a single key image more than once");
      return false;
    }

    if (!check_tx_inputs_ring_members_diff(tx))
    {
      LOG_ERROR_VER("tx uses duplicate ring members");
      return false;
    }

    if (!check_tx_input_points(tx))
    {
      LOG_ERROR_VER("tx uses key image not in the valid domain");
      return false;
    }

    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::is_output_spend_public_key_image_spent(const crypto::output_spend_public_key_image &output_spend_public_key_image) const
  {
    return m_blockchain_storage.have_tx_keyimg_as_spent(output_spend_public_key_image);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::are_output_spend_public_key_images_spent(const std::span<const crypto::output_spend_public_key_image> key_im, std::vector<bool> &spent) const
  {
    spent.clear();
    for(auto& ki: key_im)
    {
      spent.push_back(m_blockchain_storage.have_tx_keyimg_as_spent(ki));
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::are_output_spend_public_key_images_spent_in_pool(const std::span<const crypto::output_spend_public_key_image> key_im, std::vector<bool> &spent) const
  {
    spent.clear();

    return m_mempool.check_for_output_spend_public_key_images(key_im, spent);
  }
  //-----------------------------------------------------------------------------------------------
  std::pair<boost::multiprecision::uint128_t, boost::multiprecision::uint128_t> core::get_coinbase_tx_sum(const uint64_t start_offset, const size_t count)
  {
    boost::multiprecision::uint128_t emission_amount = 0;
    boost::multiprecision::uint128_t total_fee_amount = 0;

    const uint64_t end
      = count == 0
      ? get_current_blockchain_height()
      : start_offset + count - 1;

    m_blockchain_storage.for_blocks_range
      (
       start_offset
       , end
       , [this, &emission_amount, &total_fee_amount](uint64_t, const crypto::hash& hash, const block& b){

         std::vector<transaction> txs;
         std::vector<crypto::hash> missed_txs;
         uint64_t coinbase_amount = get_tx_outputs_money_amount(b.miner_tx);
         this->get_transactions(b.tx_hashes, txs, missed_txs);
         uint64_t tx_fee_amount = 0;
         for(const auto& tx: txs)
           {
             tx_fee_amount += get_tx_fee(tx);
           }

         emission_amount += coinbase_amount - tx_fee_amount;
         total_fee_amount += tx_fee_amount;
         return true;
       });

    return std::pair<boost::multiprecision::uint128_t, boost::multiprecision::uint128_t>
      (emission_amount, total_fee_amount);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_tx_inputs_keyimages_diff(const transaction& tx) const
  {
    std::unordered_set<crypto::output_spend_public_key_image> ki;
    for(const auto& in: tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, tokey_in, false);
      if(!ki.insert(tokey_in.output_spend_public_key_image).second)
        return false;
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_tx_inputs_ring_members_diff(const transaction& tx) const
  {
    return std::transform_reduce
      (
       tx.vin.begin()
       , tx.vin.end()
       , true
       , std::logical_and()
       , [](const auto& x) {

         CHECKED_GET_SPECIFIC_VARIANT(x, const txin_to_key, tokey_in, false);
         return std::transform_reduce
           (

            // Key offsets are relative increments of output indices in a blockchain
            // sorted by block height.
            // The first value can be 0. When it's 0, it references _the_ output of the coinbase
            // tx of the first block after the genesis block.
            //
            // We can verify this by playing with the `get_tx_outputs` daemon rpc call:
            //
            // echo '{"get_txid": true, "outputs":[{"index":0}]}' | http :45679/get_tx_outputs
            //
            // "outs": [
            //   {
            //     "height": 1,
            //     "key": "d2c5204259664c35c36c6d3743149359f494480ffb68b9c9885d9859201fecc5",
            //     "mask": "87050dabf5b23e8b79813f4ed76aa4add225dd2a5089af067da77ccb6ec55946",
            //     "txid": "370ae2825eb61aece7378f6a92fc22ebdc946cae751dabdf612524011a002340",
            //     "unlocked": true
            //   }
            // ],
            //
            // In other words, the tx output in genesis block is probably un-spendable, due to the
            // fact that it can not be included in a ring. :D

            std::next(tokey_in.output_relative_offsets.begin())
            , tokey_in.output_relative_offsets.end()
            , true
            , std::logical_and()
            , [](const auto& y) {
              return y != 0;
              }
            );
       }
       );
  }
  //-----------------------------------------------------------------------------------------------
  bool core::add_new_tx(transaction& tx, tx_verification_context& tvc, relay_method tx_relay, bool relayed)
  {
    const crypto::hash tx_hash = get_transaction_hash(tx);
    const string_blob tx_blob = t_serializable_object_to_blob(tx);
    const size_t tx_weight = tx_blob.size();
    return add_new_tx(tx, tx_hash, tx_blob, tx_weight, tvc, tx_relay, relayed);
  }
  //-----------------------------------------------------------------------------------------------
  size_t core::get_blockchain_total_transactions() const
  {
    return m_blockchain_storage.get_total_transactions();
  }
  //-----------------------------------------------------------------------------------------------
  bool core::add_new_tx(transaction& tx, const crypto::hash& tx_hash, const cryptonote::string_blob &blob, size_t tx_weight, tx_verification_context& tvc, relay_method tx_relay, bool relayed)
  {
    if(m_mempool.have_tx(tx_hash, relay_category::legacy))
    {
      LOG_PRINT_L2("tx " << tx_hash << "already have transaction in tx_pool");
      return true;
    }

    if(m_blockchain_storage.have_tx(tx_hash))
    {
      LOG_PRINT_L2("tx " << tx_hash << " already have transaction in blockchain");
      return true;
    }

    return m_mempool.add_tx(tx, tx_hash, blob, tx_weight, tvc, tx_relay, relayed);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::relay_txpool_transactions()
  {
    // we attempt to relay txes that should be relayed, but were not
    std::vector<std::tuple<crypto::hash, cryptonote::string_blob, relay_method>> txs;
    if (m_mempool.get_relayable_transactions(txs) && !txs.empty())
    {
      NOTIFY_NEW_TRANSACTIONS::request public_req{};
      NOTIFY_NEW_TRANSACTIONS::request private_req{};
      for (auto& tx : txs)
      {
        switch (std::get<2>(tx))
        {
          default:
          case relay_method::none:
            break;
          case relay_method::local:
            private_req.txs.push_back(std::move(std::get<1>(tx)));
            break;
          case relay_method::block:
          case relay_method::fluff:
            public_req.txs.push_back(std::move(std::get<1>(tx)));
            break;
        }
      }

      /* All txes are sent on randomized timers per connection in
         `src/cryptonote/protocol/levin_notify.cpp.` They are either sent with
         "white noise" delays or via  diffusion (Dandelion++ fluff). So
         re-relaying public and private _should_ be acceptable here. */
      const boost::uuids::uuid source = boost::uuids::nil_uuid();
      if (!public_req.txs.empty()) {
        get_protocol()->relay_transactions(public_req, source, epee::net_utils::zone::public_);
        get_protocol()->relay_transactions(public_req, source, epee::net_utils::zone::tor);
        get_protocol()->relay_transactions(public_req, source, epee::net_utils::zone::i2p);
      }
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  void core::on_transactions_relayed(const std::vector<cryptonote::string_blob> tx_blobs, const relay_method tx_relay)
  {
    std::vector<crypto::hash> tx_hashes{};
    tx_hashes.resize(tx_blobs.size());

    for (std::size_t i = 0; i < tx_blobs.size(); ++i)
    {
      cryptonote::transaction tx{};

      const auto r = cryptonote::maybe_tx_and_hash_from_blob(tx_blobs[i]);
      if (!r) {
        LOG_ERROR("Failed to parse relayed transaction");
        return;
      } else {
        std::tie(tx, tx_hashes[i]) = *r;
      }
    }
    m_mempool.set_relayed(tx_hashes, tx_relay);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_block_template(block& b, const spend_view_public_keys& adr, diff_t& diffic, uint64_t& height, uint64_t& expected_reward, const string_blob& ex_nonce)
  {
    return m_blockchain_storage.create_block_template(b, adr, diffic, height, expected_reward, ex_nonce);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_block_template(block& b, const crypto::hash *prev_block, const spend_view_public_keys& adr, diff_t& diffic, uint64_t& height, uint64_t& expected_reward, const string_blob& ex_nonce)
  {
    return m_blockchain_storage.create_block_template(b, prev_block, adr, diffic, height, expected_reward, ex_nonce);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, NOTIFY_RESPONSE_CHAIN_ENTRY::request& resp) const
  {
    return m_blockchain_storage.find_blockchain_supplement(qblock_ids, resp);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::find_blockchain_supplement(const uint64_t req_start_block, const std::list<crypto::hash>& qblock_ids, std::vector<std::pair<std::pair<cryptonote::string_blob, crypto::hash>, std::vector<std::pair<crypto::hash, cryptonote::string_blob> > > >& blocks, uint64_t& total_height, uint64_t& start_height, bool get_miner_tx_hash, size_t max_count) const
  {
    return m_blockchain_storage.find_blockchain_supplement(req_start_block, qblock_ids, blocks, total_height, start_height, get_miner_tx_hash, max_count);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_tx_outputs(const COMMAND_RPC_GET_OUTPUTS_BIN::request& req, COMMAND_RPC_GET_OUTPUTS_BIN::response& res) const
  {
    return m_blockchain_storage.get_tx_outputs(req, res);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_output_distribution(uint64_t amount, uint64_t from_height, uint64_t to_height, uint64_t &start_height, std::vector<uint64_t> &distribution, uint64_t &base) const
  {
    return m_blockchain_storage.get_output_distribution(amount, from_height, to_height, start_height, distribution, base);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_tx_outputs_gindexs(const crypto::hash& tx_id, std::vector<uint64_t>& indexs) const
  {
    return m_blockchain_storage.get_tx_outputs_gindexs(tx_id, indexs);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_tx_outputs_gindexs(const crypto::hash& tx_id, size_t n_txes, std::vector<std::vector<uint64_t>>& indexs) const
  {
    return m_blockchain_storage.get_tx_outputs_gindexs(tx_id, n_txes, indexs);
  }
  //-----------------------------------------------------------------------------------------------
  void core::pause_mine()
  {
    m_miner.pause();
  }
  //-----------------------------------------------------------------------------------------------
  void core::resume_mine()
  {
    m_miner.resume();
  }
  //-----------------------------------------------------------------------------------------------
  block_complete_entry get_block_complete_entry(block& b, tx_memory_pool &pool)
  {
    block_complete_entry bce;
    bce.block = cryptonote::block_to_blob(b);
    bce.block_weight = 0; // we can leave it to 0, those txes aren't pruned
    for (const auto &tx_hash: b.tx_hashes)
    {
      cryptonote::string_blob txblob;
      LOG_ERROR_AND_THROW_UNLESS(pool.get_transaction(tx_hash, txblob, relay_category::all), "Transaction not found in pool");
      bce.txs.push_back({txblob, crypto::null_hash});
    }
    return bce;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_block_found(block& b, block_verification_context &bvc)
  {
    bvc = {};
    m_miner.pause();
    std::vector<block_complete_entry> blocks;
    try
    {
      blocks.push_back(get_block_complete_entry(b, m_mempool));
    }
    catch (const std::exception &e)
    {
      m_miner.resume();
      return false;
    }
    std::vector<block> pblocks;
    if (!prepare_handle_incoming_blocks(blocks, pblocks))
    {
      LOG_ERROR("Block found, but failed to prepare to add");
      m_miner.resume();
      return false;
    }
    m_blockchain_storage.add_new_block(b, bvc);
    cleanup_handle_incoming_blocks(true);
    //anyway - update miner template
    update_miner_block_template();
    m_miner.resume();


    LOG_ERROR_AND_RETURN_UNLESS(!bvc.m_verifivation_failed, false, "mined block failed verification");
    if(bvc.m_added_to_main_chain)
    {
      cryptonote_connection_context exclude_context = {};
      NOTIFY_NEW_BLOCK::request arg = AUTO_VAL_INIT(arg);
      arg.current_blockchain_height = m_blockchain_storage.get_current_blockchain_height();
      std::vector<crypto::hash> missed_txs;
      std::vector<cryptonote::string_blob> txs;
      m_blockchain_storage.get_transactions_blobs(b.tx_hashes, txs, missed_txs);
      if(missed_txs.size() &&  m_blockchain_storage.get_block_id_by_height(get_block_height(b)) != get_block_hash(b))
      {
        LOG_PRINT_L1("Block found but, seems that reorganize just happened after that, do not relay this block");
        return true;
      }
      LOG_ERROR_AND_RETURN_UNLESS(txs.size() == b.tx_hashes.size() && !missed_txs.size(), false, "can't find some transactions in found block:" << get_block_hash(b) << " txs.size()=" << txs.size()
        << ", b.tx_hashes.size()=" << b.tx_hashes.size() << ", missed_txs.size()" << missed_txs.size());

      const auto maybe_block_blob = maybe_block_to_blob(b);
      LOG_ERROR_AND_RETURN_UNLESS
        (
         maybe_block_blob
         , false
         , "can't save block"
         );

      arg.b.block = *maybe_block_blob;
      //pack transactions
      for(auto& tx:  txs)
        arg.b.txs.push_back({tx, crypto::null_hash});

      m_pprotocol->relay_block(arg, exclude_context);
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  void core::on_synchronized()
  {
    m_miner.on_synchronized();
  }
  //-----------------------------------------------------------------------------------------------
  void core::safesyncmode(const bool onoff)
  {
    m_blockchain_storage.safesyncmode(onoff);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::add_new_block(const block& b, block_verification_context& bvc)
  {
    return m_blockchain_storage.add_new_block(b, bvc);
  }

  //-----------------------------------------------------------------------------------------------
  bool core::prepare_handle_incoming_blocks(const std::span<const block_complete_entry> blocks_entry, std::vector<block> &blocks)
  {
    m_incoming_tx_lock.lock();
    if (!m_blockchain_storage.prepare_handle_incoming_blocks(blocks_entry, blocks))
    {
      cleanup_handle_incoming_blocks(false);
      return false;
    }
    return true;
  }

  //-----------------------------------------------------------------------------------------------
  bool core::cleanup_handle_incoming_blocks(bool force_sync)
  {
    bool success = false;
    try {
      success = m_blockchain_storage.cleanup_handle_incoming_blocks(force_sync);
    }
    catch (...) {}
    m_incoming_tx_lock.unlock();
    return success;
  }

  //-----------------------------------------------------------------------------------------------
  bool core::handle_incoming_block(const string_blob& block_blob, const block *b, block_verification_context& bvc, bool update_miner_blocktemplate)
  {
    TRY_ENTRY();

    bvc = {};

    if (!check_incoming_block_size(block_blob))
    {
      bvc.m_verifivation_failed = true;
      return false;
    }

    if (((size_t)-1) <= 0xffffffff && block_blob.size() >= 0x3fffffff)
      LOG_WARNING("This block's size is " << block_blob.size() << ", closing on the 32 bit limit");

    block lb;
    if (!b)
    {
      crypto::hash block_hash;
      if(!parse_and_validate_block_from_blob(block_blob, lb, block_hash))
      {
        LOG_PRINT_L1("Failed to parse and validate new block");
        bvc.m_verifivation_failed = true;
        return false;
      }
      b = &lb;
    }
    add_new_block(*b, bvc);
    if(update_miner_blocktemplate && bvc.m_added_to_main_chain)
       update_miner_block_template();
    return true;

    CATCH_ENTRY_L0("core::handle_incoming_block()", false);
  }
  //-----------------------------------------------------------------------------------------------
  // Used by the RPC server to check the size of an incoming
  // block_blob
  bool core::check_incoming_block_size(const string_blob& block_blob) const
  {
    // note: we assume block weight is always >= block blob size, so we check incoming
    // blob size against the block weight limit, which acts as a sanity check without
    // having to parse/weigh first; in fact, since the block blob is the block header
    // plus the tx hashes, the weight will typically be much larger than the blob size
    const auto max_weight = get_max_block_weight(get_current_blockchain_height());
    if(block_blob.size() > max_weight + BLOCK_SIZE_SANITY_LEEWAY)
    {
      LOG_PRINT_L1("WRONG BLOCK BLOB, sanity check failed on size " << block_blob.size() << ", rejected");
      return false;
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  crypto::hash core::get_tail_id() const
  {
    return m_blockchain_storage.get_tail_id();
  }
  //-----------------------------------------------------------------------------------------------
  diff_t core::get_block_cumulative_difficulty(uint64_t height) const
  {
    return m_blockchain_storage.get_db().get_block_cumulative_difficulty(height);
  }
  //-----------------------------------------------------------------------------------------------
  size_t core::get_pool_transactions_count(bool include_sensitive_txes) const
  {
    return m_mempool.get_transactions_count(include_sensitive_txes);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::have_block_unlocked(const crypto::hash& id, int *where) const
  {
    return m_blockchain_storage.have_block_unlocked(id, where);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::have_block(const crypto::hash& id, int *where) const
  {
    return m_blockchain_storage.have_block(id, where);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::parse_tx_from_blob(transaction& tx, crypto::hash& tx_hash, const string_blob& blob) const
  {
    const auto r = cryptonote::maybe_tx_and_hash_from_blob(blob);
    if (r) {
      std::tie(tx, tx_hash) = *r;
      return true;
    } else {
      return false;
    }
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_tx_syntax(const transaction& tx) const
  {
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_transactions(std::vector<transaction>& txs, bool include_sensitive_data) const
  {
    m_mempool.get_transactions(txs, include_sensitive_data);
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_transaction_hashes(std::vector<crypto::hash>& txs, bool include_sensitive_data) const
  {
    m_mempool.get_transaction_hashes(txs, include_sensitive_data);
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_transaction_stats(struct txpool_stats& stats, bool include_sensitive_data) const
  {
    m_mempool.get_transaction_stats(stats, include_sensitive_data);
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_transaction(const crypto::hash &id, cryptonote::string_blob& tx, relay_category tx_category) const
  {
    return m_mempool.get_transaction(id, tx, tx_category);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::pool_has_tx(const crypto::hash &id) const
  {
    return m_mempool.have_tx(id, relay_category::legacy);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_transactions_and_spent_keys_info(std::vector<tx_info>& tx_infos, std::vector<spent_output_spend_public_key_image_info>& output_spend_public_key_image_infos, bool include_sensitive_data) const
  {
    return m_mempool.get_transactions_and_spent_keys_info(tx_infos, output_spend_public_key_image_infos, include_sensitive_data);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_pool_for_rpc(std::vector<cryptonote::rpc::tx_in_pool>& tx_infos, cryptonote::rpc::output_spend_public_key_images_with_tx_hashes& output_spend_public_key_image_infos) const
  {
    return m_mempool.get_pool_for_rpc(tx_infos, output_spend_public_key_image_infos);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_short_chain_history(std::list<crypto::hash>& ids) const
  {
    return m_blockchain_storage.get_short_chain_history(ids);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS::request& arg, NOTIFY_RESPONSE_GET_OBJECTS::request& rsp, cryptonote_connection_context& context)
  {
    return m_blockchain_storage.handle_get_objects(arg, rsp);
  }
  //-----------------------------------------------------------------------------------------------
  crypto::hash core::get_block_id_by_height(uint64_t height) const
  {
    return m_blockchain_storage.get_block_id_by_height(height);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_block_by_hash(const crypto::hash &h, block &blk, bool *orphan) const
  {
    return m_blockchain_storage.get_block_by_hash(h, blk, orphan);
  }
  //-----------------------------------------------------------------------------------------------
  std::string core::print_pool(bool short_format) const
  {
    return m_mempool.print_pool(short_format);
  }
  //-----------------------------------------------------------------------------------------------
  bool core::update_miner_block_template()
  {
    m_miner.on_block_chain_update();
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::on_idle()
  {
    if(!m_starter_message_showed)
    {
      if (m_offline) {
        constexpr std::string_view main_message = "The daemon is running offline.";
        LOG_GLOBAL_INFO_YELLOW
          (
           std::endl
           << "**********************************************************************" << std::endl
           << main_message << std::endl
           << "**********************************************************************" << std::endl
           );
      }
      m_starter_message_showed = true;
    }

    m_txpool_auto_relayer.do_call(std::bind(&core::relay_txpool_transactions, this));
    m_check_disk_space_interval.do_call(std::bind(&core::check_disk_space, this));
    m_block_rate_interval.do_call(std::bind(&core::check_block_rate, this));
    m_miner.on_idle();
    m_mempool.on_idle();
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_disk_space()
  {
    uint64_t free_space = get_free_space();
    if (free_space < 1ull * 1024 * 1024 * 1024) // 1 GB
    {
      const el::Level level = el::Level::Warning;
      LOG_CATEGORY_RED(level, "global", "Free space is below 1 GB on " << m_config_folder);
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  double factorial(unsigned int n)
  {
    if (n <= 1)
      return 1.0;
    double f = n;
    while (n-- > 1)
      f *= n;
    return f;
  }
  //-----------------------------------------------------------------------------------------------
  static double probability1(unsigned int blocks, unsigned int expected)
  {
    // https://www.umass.edu/wsp/resources/poisson/#computing
    return pow(expected, blocks) / (factorial(blocks) * exp(expected));
  }
  //-----------------------------------------------------------------------------------------------
  static double probability(unsigned int blocks, unsigned int expected)
  {
    double p = 0.0;
    if (blocks <= expected)
    {
      for (unsigned int b = 0; b <= blocks; ++b)
        p += probability1(b, expected);
    }
    else if (blocks > expected)
    {
      for (unsigned int b = blocks; b <= expected * 3 /* close enough */; ++b)
        p += probability1(b, expected);
    }
    return p;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::check_block_rate()
  {
    if (m_offline || m_nettype == FAKECHAIN || m_target_blockchain_height > get_current_blockchain_height() || m_target_blockchain_height == 0)
    {
      LOG_DEBUG("Not checking block rate, offline or syncing");
      return true;
    }

    static constexpr double threshold = 1. / (864000 / DIFFICULTY_TARGET_IN_SECONDS); // one false positive every 10 days
    static constexpr unsigned int max_blocks_checked = 150;

    const time_t now = time(NULL);
    const std::vector<time_t> timestamps = m_blockchain_storage.get_last_block_timestamps(max_blocks_checked);

    static const unsigned int seconds[] = { 5400, 3600, 1800, 1200, 600 };
    for (size_t n = 0; n < sizeof(seconds)/sizeof(seconds[0]); ++n)
    {
      unsigned int b = 0;
      const time_t time_boundary = now - static_cast<time_t>(seconds[n]);
      for (time_t ts: timestamps) b += ts >= time_boundary;
      const double p = probability(b, seconds[n] / DIFFICULTY_TARGET_IN_SECONDS);
      LOG_DEBUG("blocks in the last " << seconds[n] / 60 << " minutes: " << b << " (probability " << p << ")");
      if (p < threshold)
      {
        LOG_DEBUG("There were " << b << (b == max_blocks_checked ? " or more" : "") << " blocks in the last " << seconds[n] / 60 << " minutes, there might be large hash rate changes, or we might be partitioned, cut off from the Lolnero network or under attack, or your computer's time is off. Or it could be just sheer bad luck.");

        std::shared_ptr<tools::Notify> block_rate_notify = m_block_rate_notify;
        if (block_rate_notify)
        {
          auto expected = seconds[n] / DIFFICULTY_TARGET_IN_SECONDS;
          block_rate_notify->notify("%t", std::to_string(seconds[n] / 60).c_str(), "%b", std::to_string(b).c_str(), "%e", std::to_string(expected).c_str(), NULL);
        }

        break; // no need to look further
      }
    }

    return true;
  }
  //-----------------------------------------------------------------------------------------------
  void core::flush_bad_txs_cache()
  {
    bad_semantics_txes_lock.lock();
    for (int idx = 0; idx < 2; ++idx)
      bad_semantics_txes[idx].clear();
    bad_semantics_txes_lock.unlock();
  }
  //-----------------------------------------------------------------------------------------------
  void core::flush_invalid_blocks()
  {
    m_blockchain_storage.flush_invalid_blocks();
  }
  //-----------------------------------------------------------------------------------------------
  bool core::get_txpool_complement(const std::span<const crypto::hash>hashes, std::vector<cryptonote::string_blob> &txes)
  {
    return m_mempool.get_complement(hashes, txes);
  }
  //-----------------------------------------------------------------------------------------------
  void core::set_target_blockchain_height(uint64_t target_blockchain_height)
  {
    m_target_blockchain_height = target_blockchain_height;
  }
  //-----------------------------------------------------------------------------------------------
  uint64_t core::get_target_blockchain_height() const
  {
    return m_target_blockchain_height;
  }
  //-----------------------------------------------------------------------------------------------
  uint64_t core::get_free_space() const
  {
    std::filesystem::path path(m_config_folder);
    std::filesystem::space_info si = std::filesystem::space(path);
    return si.available;
  }
  //-----------------------------------------------------------------------------------------------
  bool core::has_block_weights(uint64_t height, uint64_t nblocks) const
  {
    return get_blockchain_storage().has_block_weights(height, nblocks);
  }
  //-----------------------------------------------------------------------------------------------
  std::time_t core::get_start_time() const
  {
    return start_time;
  }
  //-----------------------------------------------------------------------------------------------
  void core::graceful_exit()
  {
    raise(SIGTERM);
  }

  //-----------------------------------------------------------------------------------------------
  bool is_canonical_bulletproof_layout(const std::span<const rct::Bulletproof_unsafe> proofs)
  {
    if (proofs.size() != 1)
      return false;
    const size_t sz = proofs[0].commits.size();
    if (sz == 0 || sz > BULLETPROOF_MAX_OUTPUTS)
      return false;
    return true;
  }

  //-----------------------------------------------------------------------------------------------
  bool core::handle_incoming_tx_accumulated_batch(std::vector<tx_verification_batch_info> &tx_info, bool keeped_by_block)
  {
    bool ret = true;
    std::vector<rct::rctData> rvv;
    for (size_t n = 0; n < tx_info.size(); ++n)
    {
      if (!check_tx_semantic(*tx_info[n].tx, keeped_by_block))
      {
        set_semantics_failed(tx_info[n].tx_hash);
        tx_info[n].tvc.m_verifivation_failed = true;
        tx_info[n].result = false;
        continue;
      }

      if (tx_info[n].tx->version < 2)
        continue;
      const rct::rctData &rv = tx_info[n].tx->ringct;
      switch (rv.type) {
        case rct::RCTTypeNull:
          // coinbase should not come here, so we reject for all other types
          LOG_ERROR_VER("Unexpected Null rctData type");
          set_semantics_failed(tx_info[n].tx_hash);
          tx_info[n].tvc.m_verifivation_failed = true;
          tx_info[n].result = false;
          break;
        case rct::RCTTypeCLSAG:
          if (!is_canonical_bulletproof_layout(rv.p.bulletproofs))
          {
            LOG_ERROR_VER("Bulletproof_unsafe does not have canonical form");
            set_semantics_failed(tx_info[n].tx_hash);
            tx_info[n].tvc.m_verifivation_failed = true;
            tx_info[n].result = false;
            break;
          }
          rvv.push_back(rv); // delayed batch verification
          break;
        default:
          LOG_ERROR_VER("Unknown rct type: " << rv.type);
          set_semantics_failed(tx_info[n].tx_hash);
          tx_info[n].tvc.m_verifivation_failed = true;
          tx_info[n].result = false;
          break;
      }
    }
    if (!rvv.empty())
    {
      for (size_t n = 0; n < tx_info.size(); ++n)
      {
        if (!tx_info[n].result)
          continue;

        const rct::rctData rctData = tx_info[n].tx->ringct;

        if (rctData.type != rct::RCTTypeCLSAG)
            continue;

        // const bool valid_tx = rct::verify_ringct(rctData);
        // can't call the above since one needs to call expand_transaction_2 first lol
        const bool valid_tx_balance = verify_tx_balance(rctData) && verify_range_proof(rctData);

        if (!valid_tx_balance)
        {
          set_semantics_failed(tx_info[n].tx_hash);
          tx_info[n].tvc.m_verifivation_failed = true;
          tx_info[n].result = false;
          ret = false;
        }
      }
    }

    return ret;
  }
}
