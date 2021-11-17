// Copyright (c) 2014-2020, The Monero Project
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

#include "blockchain.h"
#include "tx_pool.h"
#include "core_type.h"

#include "cryptonote/tx/functional/tx_check.h"
#include "cryptonote/functional/helper.hpp"

#include "math/ringct/pseudo_functional/rctSigs.hpp"

#include "tools/common/threadpool.h"
#include "tools/common/notify.h"
#include "tools/epee/include/profile_tools.h"
#include "tools/epee/include/time_helper.h"

#include <boost/range/adaptor/reversed.hpp>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "blockchain"

#define FIND_BLOCKCHAIN_SUPPLEMENT_MAX_SIZE (100*1024*1024) // 100 MB

using namespace cryptonote;

#define LOG_ERROR_VER(x) LOG_CATEGORY_ERROR("verify", x)

std::recursive_mutex m_blockchain_lock; // TODO: add here reader/writer lock

//------------------------------------------------------------------
Blockchain::Blockchain(tx_memory_pool& tx_pool) :
  m_db(), m_tx_pool(tx_pool), m_timestamps_and_difficulties_height(0), m_reset_timestamps_and_difficulties_height(true),
  m_db_sync_on_blocks(true), m_db_sync_threshold(1), m_db_sync_mode(db_async), m_db_default_sync(false), m_show_time_stats(false), m_sync_counter(0), m_bytes_to_sync(0), m_cancel(false),
  m_difficulty_for_next_block_top_hash(crypto::null_hash),
  m_difficulty_for_next_block(1),
  m_btc_valid(false),
  m_batch_success(true),
  m_prepare_height(0)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
}
//------------------------------------------------------------------
Blockchain::~Blockchain()
{
  try { deinit(); }
  catch (const std::exception &e) { /* ignore */ }
}
//------------------------------------------------------------------
bool Blockchain::have_tx(const crypto::hash &id) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->tx_exists(id);
}
//------------------------------------------------------------------
bool Blockchain::have_tx_keyimg_as_spent(const crypto::output_spend_public_key_image &key_im) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return  m_db->has_output_spend_public_key_image(key_im);
}
//------------------------------------------------------------------
// This function makes sure that each "input" in an input (mixins) exists
// and collects the public key for each from the transaction it was included in
// via the visitor passed to it.
template <class visitor_t>
bool Blockchain::scan_outputkeys_for_indexes(size_t tx_version, const txin_to_key& tx_in_to_key, visitor_t &vis, const crypto::hash &tx_prefix_hash, uint64_t* pmax_related_block_height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  // ND: Disable locking and make method private.
  //LOCK_RECURSIVE_MUTEX(m_blockchain_lock);

  // verify that the input has key offsets (that it exists properly, really)
  if(!tx_in_to_key.output_relative_offsets.size())
    return false;

  // cryptonote_format_utils uses relative offsets for indexing to the global
  // outputs list.  that is to say that absolute offset #2 is absolute offset
  // #1 plus relative offset #2.
  // TODO: Investigate if this is necessary / why this is done.
  std::vector<uint64_t> absolute_offsets = relative_output_offsets_to_absolute(tx_in_to_key.output_relative_offsets);
  std::vector<output_data_t> outputs;

  bool found = false;
  auto it = m_scan_table.find(tx_prefix_hash);
  if (it != m_scan_table.end())
  {
    auto its = it->second.find(tx_in_to_key.output_spend_public_key_image);
    if (its != it->second.end())
    {
      outputs = its->second;
      found = true;
    }
  }

  if (!found)
  {
    try
    {
      m_db->get_output_key(std::span<const uint64_t>(&tx_in_to_key.amount, 1), absolute_offsets, outputs, true);
      if (absolute_offsets.size() != outputs.size())
      {
        LOG_ERROR_VER("Output does not exist! amount = " << tx_in_to_key.amount);
        return false;
      }
    }
    catch (...)
    {
      LOG_ERROR_VER("Output does not exist! amount = " << tx_in_to_key.amount);
      return false;
    }
  }
  else
  {
    // check for partial results and add the rest if needed;
    if (outputs.size() < absolute_offsets.size() && outputs.size() > 0)
    {
      LOG_DEBUG("Additional outputs needed: " << absolute_offsets.size() - outputs.size());
      std::vector < uint64_t > add_offsets;
      std::vector<output_data_t> add_outputs;
      add_outputs.reserve(absolute_offsets.size() - outputs.size());
      for (size_t i = outputs.size(); i < absolute_offsets.size(); i++)
        add_offsets.push_back(absolute_offsets[i]);
      try
      {
        m_db->get_output_key(std::span<const uint64_t>(&tx_in_to_key.amount, 1), add_offsets, add_outputs, true);
        if (add_offsets.size() != add_outputs.size())
        {
          LOG_ERROR_VER("Output does not exist! amount = " << tx_in_to_key.amount);
          return false;
        }
      }
      catch (...)
      {
        LOG_ERROR_VER("Output does not exist! amount = " << tx_in_to_key.amount);
        return false;
      }
      outputs.insert(outputs.end(), add_outputs.begin(), add_outputs.end());
    }
  }

  size_t count = 0;
  for (const uint64_t& i : absolute_offsets)
  {
    try
    {
      output_data_t output_index;
      try
      {
        // get tx hash and output index for output
        if (count < outputs.size())
          output_index = outputs.at(count);
        else
          output_index = m_db->get_output_key(tx_in_to_key.amount, i);

        // call to the passed boost visitor to grab the public key for the output
        if (!vis.handle_output(output_index.unlock_time, output_index.pubkey, output_index.commitment))
        {
          LOG_ERROR_VER("Failed to handle_output for output no = " << count << ", with absolute offset " << i);
          return false;
        }
      }
      catch (...)
      {
        LOG_ERROR_VER("Output does not exist! amount = " << tx_in_to_key.amount << ", absolute_offset = " << i);
        return false;
      }

      // if on last output and pmax_related_block_height not null pointer
      if(++count == absolute_offsets.size() && pmax_related_block_height)
      {
        // set *pmax_related_block_height to tx block height for this output
        auto h = output_index.height;
        if(*pmax_related_block_height < h)
        {
          *pmax_related_block_height = h;
        }
      }

    }
    catch (const OUTPUT_DNE& e)
    {
      LOG_ERROR_VER("Output does not exist: " << e.what());
      return false;
    }
    catch (const TX_DNE& e)
    {
      LOG_ERROR_VER("Transaction does not exist: " << e.what());
      return false;
    }

  }

  return true;
}
//------------------------------------------------------------------
uint64_t Blockchain::get_current_blockchain_height() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->height();
}
//------------------------------------------------------------------
//FIXME: possibly move this into the constructor, to avoid accidentally
//       dereferencing a null BlockchainDB pointer
bool Blockchain::init(BlockchainDB* db, const network_type nettype, bool offline, diff_t fixed_difficulty)
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  LOCK_LOCKABLE_OBJECT(m_tx_pool);
  std::lock_guard<std::recursive_mutex> lock1(m_blockchain_lock);

  if (db == nullptr)
  {
    LOG_ERROR("Attempted to init Blockchain with null DB");
    return false;
  }
  if (!db->is_open())
  {
    LOG_ERROR("Attempted to init Blockchain with unopened DB");
    delete db;
    return false;
  }

  m_db = db;

  m_nettype = nettype;
  m_offline = offline;
  m_fixed_difficulty = fixed_difficulty;

  // if the blockchain is new, add the genesis block
  // this feels kinda kludgy to do it this way, but can be looked at later.
  // TODO: add function to create and store genesis block,
  //       taking testnet into account
  if(!m_db->height())
  {
    LOG_INFO("Blockchain not loaded, generating genesis block.");
    const auto bl = generate_genesis_block(get_config(m_nettype).GENESIS_TX, get_config(m_nettype).GENESIS_NONCE);
    if (!bl) return false;
    db_wtxn_guard wtxn_guard(m_db);
    block_verification_context bvc = {};
    add_new_block(*bl, bvc);
    LOG_ERROR_AND_RETURN_UNLESS(!bvc.m_verifivation_failed, false, "Failed to add genesis block to blockchain");
  }
  // TODO: if blockchain load successful, verify blockchain against both
  //       hard-coded and runtime-loaded (and enforced) checkpoints.
  else
  {
  }

  if (m_nettype != FAKECHAIN)
  {
    // ensure we fixup anything we found and fix in the future
    m_db->fixup();
  }

  db_rtxn_guard rtxn_guard(m_db);

  // check how far behind we are
  uint64_t top_block_timestamp = m_db->get_top_block_timestamp();
  uint64_t timestamp_diff = time(NULL) - top_block_timestamp;

  // genesis block has no timestamp, could probably change it to have timestamp of 1522624244 (2018-04-01 23:10:44, block 1)...
  if(!top_block_timestamp)
    timestamp_diff = time(NULL) - 1602198644;

  // create general purpose async service queue

  // we only need 1
  m_async_pool.emplace_back(std::thread([this](){this->m_async_service.run();}));

  LOG_INFO("Blockchain initialized. last block: " << m_db->height() - 1 << ", " << epee::misc_utils::get_time_interval_string(timestamp_diff) << " time ago, current difficulty: " << get_difficulty_for_next_block());

  rtxn_guard.stop();

  uint64_t num_popped_blocks = 0;
  if (num_popped_blocks > 0)
  {
    m_timestamps_and_difficulties_height = 0;
    m_reset_timestamps_and_difficulties_height = true;
    uint64_t top_block_height;
    crypto::hash top_block_hash = get_tail_id(top_block_height);
    m_tx_pool.on_blockchain_dec(top_block_height, top_block_hash);
  }

  {
    db_txn_guard txn_guard(m_db, m_db->is_read_only());
    if (!update_next_cumulative_weight_limit())
      return false;
  }
  return true;
}
//------------------------------------------------------------------
bool Blockchain::init(BlockchainDB* db, const network_type nettype, bool offline)
{
  bool res = init(db, nettype, offline, NULL);
  return res;
}
//------------------------------------------------------------------
bool Blockchain::store_blockchain()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // lock because the rpc_thread command handler also calls this
  std::unique_lock<std::mutex> lock(m_db->m_synchronization_lock);

  TIME_MEASURE_START(save);
  // TODO: make sure sync(if this throws that it is not simply ignored higher
  // up the call stack
  try
  {
    m_db->sync();
  }
  catch (const std::exception& e)
  {
    LOG_ERROR(std::string("Error syncing blockchain db: ") + e.what() + "-- shutting down now to prevent issues!");
    throw;
  }
  catch (...)
  {
    LOG_ERROR("There was an issue storing the blockchain, shutting down now to prevent issues!");
    throw;
  }

  TIME_MEASURE_FINISH(save);
  if(m_show_time_stats)
    LOG_INFO("Blockchain stored OK, took: " << save << " ms");
  return true;
}
//------------------------------------------------------------------
bool Blockchain::deinit()
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  LOG_TRACE("Stopping blockchain read/write activity");

 // stop async service

  for (auto& thread : m_async_pool) {
    thread.join();
  }

  m_async_service.stop();

  // as this should be called if handling a SIGSEGV, need to check
  // if m_db is a NULL pointer (and thus may have caused the illegal
  // memory operation), otherwise we may cause a loop.
  try
  {
    if (m_db)
    {
      m_db->close();
      LOG_TRACE("Local blockchain read/write activity stopped successfully");
    }
  }
  catch (const std::exception& e)
  {
    LOG_ERROR(std::string("Error closing blockchain db: ") + e.what());
  }
  catch (...)
  {
    LOG_ERROR("There was an issue closing/storing the blockchain, shutting down now to prevent issues!");
  }

  delete m_db;
  m_db = NULL;
  return true;
}
//------------------------------------------------------------------
// This function removes blocks from the top of blockchain.
// It starts a batch and calls private method pop_block_from_blockchain().
void Blockchain::pop_blocks(uint64_t nblocks)
{
  uint64_t i = 0;
  LOCK_LOCKABLE_OBJECT(m_tx_pool);
  std::lock_guard<std::recursive_mutex> lock1(m_blockchain_lock);

  bool stop_batch = m_db->batch_start();

  try
  {
    const uint64_t blockchain_height = m_db->height();
    if (blockchain_height > 0)
      nblocks = std::min(nblocks, blockchain_height - 1);
    while (i < nblocks)
    {
      pop_block_from_blockchain();
      ++i;
    }
  }
  catch (const std::exception& e)
  {
    LOG_ERROR("Error when popping blocks after processing " << i << " blocks: " << e.what());
    if (stop_batch)
      m_db->batch_abort();
    return;
  }

  if (stop_batch)
    m_db->batch_stop();
}
//------------------------------------------------------------------
// This function tells BlockchainDB to remove the top block from the
// blockchain and then returns all transactions (except the miner tx, of course)
// from it to the tx_pool
block Blockchain::pop_block_from_blockchain()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);

  m_timestamps_and_difficulties_height = 0;
  m_reset_timestamps_and_difficulties_height = true;

  block popped_block;
  std::vector<transaction> popped_txs;

  LOG_ERROR_AND_THROW_UNLESS(m_db->height() > 1, "Cannot pop the genesis block");

  try
  {
    m_db->pop_block(popped_block, popped_txs);
  }
  // anything that could cause this to throw is likely catastrophic,
  // so we re-throw
  catch (const std::exception& e)
  {
    LOG_ERROR("Error popping block from blockchain: " << e.what());
    throw;
  }
  catch (...)
  {
    LOG_ERROR("Error popping block from blockchain, throwing!");
    throw;
  }

  // return transactions from popped block to the tx_pool
  for (transaction& tx : popped_txs)
  {
    if (!is_coinbase(tx))
    {
      cryptonote::tx_verification_context tvc = AUTO_VAL_INIT(tvc);

      // We assume that if they were in a block, the transactions are already
      // known to the network as a whole. However, if we had mined that block,
      // that might not be always true. Unlikely though, and always relaying
      // these again might cause a spike of traffic as many nodes re-relay
      // all the transactions in a popped block when a reorg happens.
      bool r = m_tx_pool.add_tx(tx, tvc, relay_method::block, true);
      if (!r)
      {
        LOG_ERROR("Error returning transaction to tx_pool");
      }
    }
  }

  m_blocks_longhash_table.clear();
  m_scan_table.clear();
  m_blocks_txs_check.clear();

  LOG_ERROR_AND_THROW_UNLESS(update_next_cumulative_weight_limit(), "Error updating next cumulative weight limit");
  uint64_t top_block_height;
  crypto::hash top_block_hash = get_tail_id(top_block_height);
  m_tx_pool.on_blockchain_dec(top_block_height, top_block_hash);
  invalidate_block_template_cache();

  return popped_block;
}
//------------------------------------------------------------------
bool Blockchain::reset_and_set_genesis_block(const block& b)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  m_timestamps_and_difficulties_height = 0;
  m_reset_timestamps_and_difficulties_height = true;
  invalidate_block_template_cache();
  m_db->reset();
  m_db->drop_alt_blocks();

  db_wtxn_guard wtxn_guard(m_db);
  block_verification_context bvc = {};
  add_new_block(b, bvc);
  if (!update_next_cumulative_weight_limit())
    return false;
  return bvc.m_added_to_main_chain && !bvc.m_verifivation_failed;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_tail_id(uint64_t& height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  return m_db->top_block_hash(&height);
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_tail_id() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->top_block_hash();
}
//------------------------------------------------------------------
/*TODO: this function was...poorly written.  As such, I'm not entirely
 *      certain on what it was supposed to be doing.  Need to look into this,
 *      but it doesn't seem terribly important just yet.
 *
 * puts into list <ids> a list of hashes representing certain blocks
 * from the blockchain in reverse chronological order
 *
 * the blocks chosen, at the time of this writing, are:
 *   the most recent 11
 *   powers of 2 less recent from there, so 13, 17, 25, etc...
 *
 */
bool Blockchain::get_short_chain_history(std::list<crypto::hash>& ids) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  uint64_t i = 0;
  uint64_t current_multiplier = 1;
  uint64_t sz = m_db->height();

  if(!sz)
    return true;

  db_rtxn_guard rtxn_guard(m_db);
  bool genesis_included = false;
  uint64_t current_back_offset = 1;
  while(current_back_offset < sz)
  {
    ids.push_back(m_db->get_block_hash_from_height(sz - current_back_offset));

    if(sz-current_back_offset == 0)
    {
      genesis_included = true;
    }
    if(i < 10)
    {
      ++current_back_offset;
    }
    else
    {
      current_multiplier *= 2;
      current_back_offset += current_multiplier;
    }
    ++i;
  }

  if (!genesis_included)
  {
    ids.push_back(m_db->get_block_hash_from_height(0));
  }

  return true;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_block_id_by_height(uint64_t height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  try
  {
    return m_db->get_block_hash_from_height(height);
  }
  catch (const BLOCK_DNE& e)
  {
  }
  catch (const std::exception& e)
  {
    LOG_ERROR(std::string("Something went wrong fetching block hash by height: ") + e.what());
    throw;
  }
  catch (...)
  {
    LOG_ERROR(std::string("Something went wrong fetching block hash by height"));
    throw;
  }
  return crypto::null_hash;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_pending_block_id_by_height(uint64_t height) const
{
  return get_block_id_by_height(height);
}
//------------------------------------------------------------------
bool Blockchain::get_block_by_hash(const crypto::hash &h, block &blk, bool *orphan) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  // try to find block in main chain
  try
  {
    blk = m_db->get_block(h);
    if (orphan)
      *orphan = false;
    return true;
  }
  // try to find block in alternative chain
  catch (const BLOCK_DNE& e)
  {
    const auto r = m_db->get_alt_block(h);
    if (r)
    {
      const auto& [data, blob] = *r;
      const auto maybeBlock = maybe_block_from_blob(blob);
      if (!maybeBlock)
      {
        LOG_ERROR("Found block " << h << " in alt chain, but failed to parse it");
        throw std::runtime_error("Found block in alt chain, but failed to parse it");
      }
      blk = *maybeBlock;
      if (orphan)
        *orphan = true;
      return true;
    }
  }
  catch (const std::exception& e)
  {
    LOG_ERROR(std::string("Something went wrong fetching block by hash: ") + e.what());
    throw;
  }
  catch (...)
  {
    LOG_ERROR(std::string("Something went wrong fetching block hash by hash"));
    throw;
  }

  return false;
}
//------------------------------------------------------------------
// This function aggregates the cumulative difficulties and timestamps of the
// last DIFFICULTY_BLOCKS_COUNT blocks and passes them to next_difficulty,
// returning the result of that call.  Ignores the genesis block, and can use
// less blocks than desired if there aren't enough.
diff_t Blockchain::get_difficulty_for_next_block()
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  std::stringstream ss;
  bool print = false;

  int done = 0;
  ss << "get_difficulty_for_next_block: height " << m_db->height() << std::endl;
  if (m_fixed_difficulty)
  {
    return m_db->height() ? m_fixed_difficulty : 1;
  }

start:
  diff_t D = 0;

  crypto::hash top_hash = get_tail_id();
  {
    LOCK_RECURSIVE_MUTEX(m_difficulty_lock);
    // we can call this without the blockchain lock, it might just give us
    // something a bit out of date, but that's fine since anything which
    // requires the blockchain lock will have acquired it in the first place,
    // and it will be unlocked only when called from the getinfo RPC
    ss << "Locked, tail id " << top_hash << ", cached is " << m_difficulty_for_next_block_top_hash << std::endl;
    if (top_hash == m_difficulty_for_next_block_top_hash)
    {
      ss << "Same, using cached diff " << m_difficulty_for_next_block << std::endl;
      D = m_difficulty_for_next_block;
    }
  }

  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  std::vector<uint64_t> timestamps;
  std::vector<diff_t> difficulties;
  uint64_t height;
  auto new_top_hash = get_tail_id(height); // get it again now that we have the lock
  ++height;
  if (!(new_top_hash == top_hash)) D=0;
  ss << "Re-locked, height " << height << ", tail id " << new_top_hash << (new_top_hash == top_hash ? "" : " (different)") << std::endl;
  top_hash = new_top_hash;
  uint64_t difficulty_blocks_count = DIFFICULTY_BLOCKS_COUNT;

  // ND: Speedup
  // 1. Keep a list of the last 735 (or less) blocks that is used to compute difficulty,
  //    then when the next block difficulty is queried, push the latest height data and
  //    pop the oldest one from the list. This only requires 1x read per height instead
  //    of doing 735 (DIFFICULTY_BLOCKS_COUNT).
  bool check = false;
  if (m_reset_timestamps_and_difficulties_height)
    m_timestamps_and_difficulties_height = 0;
  if (m_timestamps_and_difficulties_height != 0 && ((height - m_timestamps_and_difficulties_height) == 1) && m_timestamps.size() >= difficulty_blocks_count)
  {
    uint64_t index = height - 1;
    m_timestamps.push_back(m_db->get_block_timestamp(index));
    m_difficulties.push_back(m_db->get_block_cumulative_difficulty(index));

    while (m_timestamps.size() > difficulty_blocks_count)
      m_timestamps.erase(m_timestamps.begin());
    while (m_difficulties.size() > difficulty_blocks_count)
      m_difficulties.erase(m_difficulties.begin());

    m_timestamps_and_difficulties_height = height;
    timestamps = m_timestamps;
    difficulties = m_difficulties;
    check = true;
  }
  //else
  std::vector<uint64_t> timestamps_from_cache = timestamps;
  std::vector<diff_t> difficulties_from_cache = difficulties;

  {
    uint64_t offset = height - std::min <uint64_t> (height, static_cast<uint64_t>(difficulty_blocks_count));
    if (offset == 0)
      ++offset;

    timestamps.clear();
    difficulties.clear();
    if (height > offset)
    {
      timestamps.reserve(height - offset);
      difficulties.reserve(height - offset);
    }
    ss << "Looking up " << (height - offset) << " from " << offset << std::endl;
    for (; offset < height; offset++)
    {
      timestamps.push_back(m_db->get_block_timestamp(offset));
      difficulties.push_back(m_db->get_block_cumulative_difficulty(offset));
    }

    if (check) if (timestamps != timestamps_from_cache || difficulties !=difficulties_from_cache)
    {
      ss << "Inconsistency XXX:" << std::endl;
      ss << "top hash: "<<top_hash << std::endl;
      ss << "timestamps: " << timestamps_from_cache.size() << " from cache, but " << timestamps.size() << " without" << std::endl;
      ss << "difficulties: " << difficulties_from_cache.size() << " from cache, but " << difficulties.size() << " without" << std::endl;
      ss << "timestamps_from_cache:" << std::endl; for (const auto &v :timestamps_from_cache) ss << "  " << v << std::endl;
      ss << "timestamps:" << std::endl; for (const auto &v :timestamps) ss << "  " << v << std::endl;
      ss << "difficulties_from_cache:" << std::endl; for (const auto &v :difficulties_from_cache) ss << "  " << v << std::endl;
      ss << "difficulties:" << std::endl; for (const auto &v :difficulties) ss << "  " << v << std::endl;

      uint64_t dbh = m_db->height();
      uint64_t sh = dbh < 10000 ? 0 : dbh - 10000;
      ss << "History from -10k at :" << dbh << ", from " << sh << std::endl;
      for (uint64_t h = sh; h < dbh; ++h)
      {
        uint64_t ts = m_db->get_block_timestamp(h);
        diff_t d = m_db->get_block_cumulative_difficulty(h);
        ss << "  " << h << " " << ts << " " << d << std::endl;
      }
      print = true;
    }
    m_timestamps_and_difficulties_height = height;
    m_timestamps = timestamps;
    m_difficulties = difficulties;
  }

  const diff_t diff =
    next_difficulty
    (
     timestamps
     , difficulties
     , m_db->height()
     );

  LOCK_RECURSIVE_MUTEX(m_difficulty_lock);
  m_difficulty_for_next_block_top_hash = top_hash;
  m_difficulty_for_next_block = diff;
  if (D && D != diff && m_nettype == MAINNET)
  {
    ss << "XXX Mismatch at " << height << "/" << top_hash << "/" << get_tail_id() << ": cached " << D << ", real " << diff << std::endl;
    print = true;
  }

  ++done;
  if (done == 1 && D && D != diff && m_nettype == MAINNET)
  {
    print = true;
    ss << "Might be a race. Let's see what happens if we try again..." << std::endl;
    epee::misc_utils::sleep_no_w(100);
    goto start;
  }
  ss << "Diff for " << top_hash << ": " << diff << std::endl;
  if (print && m_nettype == MAINNET)
  {
    LOG_GLOBAL_INFO("START DUMP");
    LOG_GLOBAL_INFO(ss.str());
    LOG_GLOBAL_INFO("END DUMP");
  }
  return diff;
}
//------------------------------------------------------------------
std::vector<time_t> Blockchain::get_last_block_timestamps(unsigned int blocks) const
{
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  uint64_t height = m_db->height();
  if (blocks > height)
    blocks = height;
  std::vector<time_t> timestamps(blocks);
  while (blocks--)
    timestamps[blocks] = m_db->get_block_timestamp(height - blocks - 1);
  return timestamps;
}
//------------------------------------------------------------------
// This function removes blocks from the blockchain until it gets to the
// position where the blockchain switch started and then re-adds the blocks
// that had been removed.
bool Blockchain::rollback_blockchain_switching(std::list<block>& original_chain, uint64_t rollback_height)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);

  // fail if rollback_height passed is too high
  if (rollback_height > m_db->height())
  {
    return true;
  }

  m_timestamps_and_difficulties_height = 0;
  m_reset_timestamps_and_difficulties_height = true;

  // remove blocks from blockchain until we get back to where we should be.
  while (m_db->height() != rollback_height)
  {
    pop_block_from_blockchain();
  }

  //return back original chain
  for (auto& bl : original_chain)
  {
    block_verification_context bvc = {};
    bool r = handle_block_to_main_chain(bl, bvc, false);
    LOG_ERROR_AND_RETURN_UNLESS(r && bvc.m_added_to_main_chain, false, "PANIC! failed to add (again) block while chain switching during the rollback!");
  }

  LOG_INFO("Rollback to height " << rollback_height << " was successful.");
  if (!original_chain.empty())
  {
    LOG_INFO("Restoration to previous blockchain successful as well.");
  }
  return true;
}
//------------------------------------------------------------------
// This function attempts to switch to an alternate chain, returning
// boolean based on success therein.
bool Blockchain::switch_to_alternative_blockchain(std::list<block_extended_info>& alt_chain, bool discard_disconnected_chain)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);

  m_timestamps_and_difficulties_height = 0;
  m_reset_timestamps_and_difficulties_height = true;

  // if empty alt chain passed (not sure how that could happen), return false
  LOG_ERROR_AND_RETURN_UNLESS(alt_chain.size(), false, "switch_to_alternative_blockchain: empty chain passed");

  // verify that main chain has front of alt chain's parent block
  if (!m_db->block_exists(alt_chain.front().bl.prev_id))
  {
    LOG_ERROR("Attempting to move to an alternate chain, but it doesn't appear to connect to the main chain!");
    return false;
  }

  // pop blocks from the blockchain until the top block is the parent
  // of the front block of the alt chain.
  std::list<block> disconnected_chain;
  while (m_db->top_block_hash() != alt_chain.front().bl.prev_id)
  {
    block b = pop_block_from_blockchain();
    disconnected_chain.push_front(b);
  }

  auto split_height = m_db->height();

  //connecting new alternative chain
  for(auto alt_ch_iter = alt_chain.begin(); alt_ch_iter != alt_chain.end(); alt_ch_iter++)
  {
    const auto &bei = *alt_ch_iter;
    block_verification_context bvc = {};

    // add block to main chain
    bool r = handle_block_to_main_chain(bei.bl, bvc, false);

    // if adding block to main chain failed, rollback to previous state and
    // return false
    if(!r || !bvc.m_added_to_main_chain)
    {
      LOG_ERROR("Failed to switch to alternative blockchain");

      // rollback_blockchain_switching should be moved to two different
      // functions: rollback and apply_chain, but for now we pretend it is
      // just the latter (because the rollback was done above).
      rollback_blockchain_switching(disconnected_chain, split_height);

      // FIXME: Why do we keep invalid blocks around?  Possibly in case we hear
      // about them again so we can immediately dismiss them, but needs some
      // looking into.
      const crypto::hash blkid = cryptonote::get_block_hash(bei.bl);
      add_block_as_invalid(bei, blkid);
      LOG_ERROR("The block was inserted as invalid while connecting new alternative chain, block_id: " << blkid);
      m_db->remove_alt_block(blkid);
      alt_ch_iter++;

      for(auto alt_ch_to_orph_iter = alt_ch_iter; alt_ch_to_orph_iter != alt_chain.end(); )
      {
        const auto &bei = *alt_ch_to_orph_iter++;
        const crypto::hash blkid = cryptonote::get_block_hash(bei.bl);
        add_block_as_invalid(bei, blkid);
        m_db->remove_alt_block(blkid);
      }
      return false;
    }
  }

  // if we're to keep the disconnected blocks, add them as alternates
  const size_t discarded_blocks = disconnected_chain.size();
  if(!discard_disconnected_chain)
  {
    //pushing old chain as alternative chain
    for (auto& old_ch_ent : disconnected_chain)
    {
      block_verification_context bvc = {};
      bool r = handle_alternative_block(old_ch_ent, get_block_hash(old_ch_ent), bvc);
      if(!r)
      {
        LOG_ERROR("Failed to push ex-main chain blocks to alternative chain ");
        // previously this would fail the blockchain switching, but I don't
        // think this is bad enough to warrant that.
      }
    }
  }

  //removing alt_chain entries from alternative chains container
  for (const auto &bei: alt_chain)
  {
    m_db->remove_alt_block(cryptonote::get_block_hash(bei.bl));
  }

  std::shared_ptr<tools::Notify> reorg_notify = m_reorg_notify;
  if (reorg_notify)
    reorg_notify->notify("%s", std::to_string(split_height).c_str(), "%h", std::to_string(m_db->height()).c_str(),
        "%n", std::to_string(m_db->height() - split_height).c_str(), "%d", std::to_string(discarded_blocks).c_str(), NULL);

  for (const auto& notifier : m_block_notifiers)
  {
    std::size_t notify_height = split_height;
    for (const auto& bei: alt_chain)
    {
      notifier(notify_height, std::vector{bei.bl});
      ++notify_height;
    }
  }

  LOG_GLOBAL_INFO_GREEN("REORGANIZE SUCCESS! on height: " << split_height << ", new blockchain size: " << m_db->height());
  return true;
}
//------------------------------------------------------------------
// This function calculates the difficulty target for the block being added to
// an alternate chain.
diff_t Blockchain::get_next_difficulty_for_alternative_chain(const std::list<block_extended_info>& alt_chain, block_extended_info& bei) const
{
  if (m_fixed_difficulty)
  {
    return m_db->height() ? m_fixed_difficulty : 1;
  }

  LOG_PRINT_L3("Blockchain::" << __func__);
  std::vector<uint64_t> timestamps;
  std::vector<diff_t> cumulative_difficulties;

  size_t difficulty_blocks_count = DIFFICULTY_BLOCKS_COUNT;

  // if the alt chain isn't long enough to calculate the difficulty target
  // based on its blocks alone, need to get more blocks from the main chain
  if(alt_chain.size()< difficulty_blocks_count)
  {
    std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);

    // Figure out start and stop offsets for main chain blocks
    size_t main_chain_stop_offset = alt_chain.size() ? alt_chain.front().height : bei.height;
    size_t main_chain_count = difficulty_blocks_count - std::min(static_cast<size_t>(difficulty_blocks_count), alt_chain.size());
    main_chain_count = std::min(main_chain_count, main_chain_stop_offset);
    size_t main_chain_start_offset = main_chain_stop_offset - main_chain_count;

    if(!main_chain_start_offset)
      ++main_chain_start_offset; //skip genesis block

    // get difficulties and timestamps from relevant main chain blocks
    for(; main_chain_start_offset < main_chain_stop_offset; ++main_chain_start_offset)
    {
      timestamps.push_back(m_db->get_block_timestamp(main_chain_start_offset));
      cumulative_difficulties.push_back(m_db->get_block_cumulative_difficulty(main_chain_start_offset));
    }

    // make sure we haven't accidentally grabbed too many blocks...maybe don't need this check?
    LOG_ERROR_AND_RETURN_UNLESS((alt_chain.size() + timestamps.size()) <= difficulty_blocks_count, false, "Internal error, alt_chain.size()[" << alt_chain.size() << "] + vtimestampsec.size()[" << timestamps.size() << "] NOT <= DIFFICULTY_WINDOW[]" << difficulty_blocks_count);

    for (const auto &bei : alt_chain)
    {
      timestamps.push_back(bei.bl.timestamp);
      cumulative_difficulties.push_back(bei.cumulative_difficulty);
    }
  }
  // if the alt chain is long enough for the difficulty calc, grab difficulties
  // and timestamps from it alone
  else
  {
    timestamps.resize(static_cast<size_t>(difficulty_blocks_count));
    cumulative_difficulties.resize(static_cast<size_t>(difficulty_blocks_count));
    size_t count = 0;
    size_t max_i = timestamps.size()-1;
    // get difficulties and timestamps from most recent blocks in alt chain
    for (const auto &bei: boost::adaptors::reverse(alt_chain))
    {
      timestamps[max_i - count] = bei.bl.timestamp;
      cumulative_difficulties[max_i - count] = bei.cumulative_difficulty;
      count++;
      if(count >= difficulty_blocks_count)
        break;
    }
  }

  return next_difficulty
    (
     timestamps
     , cumulative_difficulties
     , m_db->height()
     );
}
//------------------------------------------------------------------
// This function does a sanity check on basic things that all miner
// transactions have in common, such as:
//   one input, of type txin_gen, with height set to the block's height
//   correct miner tx unlock time
//   a non-overflowing tx amount (dubious necessity on this check)
bool Blockchain::prevalidate_miner_transaction(const block& b, uint64_t height)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  LOG_ERROR_AND_RETURN_UNLESS(b.miner_tx.vin.size() == 1, false, "coinbase transaction in the block has no inputs");
  LOG_ERROR_AND_RETURN_UNLESS(b.miner_tx.vin[0].type() == typeid(txin_gen), false, "coinbase transaction in the block has the wrong type");

  if (height == 0) return true;
  LOG_ERROR_AND_RETURN_UNLESS(b.miner_tx.version > 1, false, "Invalid coinbase transaction version");

  // for v2 txes (ringct), we only accept empty rct signatures for miner transactions,
  if (b.miner_tx.version >= 2)
  {
    LOG_ERROR_AND_RETURN_UNLESS(b.miner_tx.ringct.type == rct::RCTTypeNull, false, "RingCT signatures not allowed in coinbase transactions");
  }

  if(boost::get<txin_gen>(b.miner_tx.vin[0]).height != height)
  {
    LOG_WARNING("The miner transaction in block has invalid height: " << boost::get<txin_gen>(b.miner_tx.vin[0]).height << ", expected: " << height);
    return false;
  }
  LOG_DEBUG("Miner tx hash: " << get_transaction_hash(b.miner_tx));
  LOG_ERROR_AND_RETURN_UNLESS(b.miner_tx.unlock_time == height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, false, "coinbase transaction transaction has the wrong unlock time=" << b.miner_tx.unlock_time << ", expected " << height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);

  //check outs overflow
  //NOTE: not entirely sure this is necessary, given that this function is
  //      designed simply to make sure the total amount for a transaction
  //      does not overflow a uint64_t, and this transaction *is* a uint64_t...
  if(!check_outs_overflow(b.miner_tx))
  {
    LOG_ERROR("miner transaction has money overflow in block " << get_block_hash(b));
    return false;
  }

  return check_tx_output_points(b.miner_tx);
}
//------------------------------------------------------------------
// This function validates the miner transaction reward
bool Blockchain::validate_miner_transaction(const block& b, size_t cumulative_block_weight, uint64_t fee, uint64_t& base_reward, bool &partial_block_reward)
{
  uint64_t height = cryptonote::get_block_height(b);
  if (height == 0) return true;

  LOG_PRINT_L3("Blockchain::" << __func__);
  //validate reward
  uint64_t money_in_use = 0;
  for (auto& o: b.miner_tx.vout)
    money_in_use += o.amount;
  partial_block_reward = false;

  if (!check_block_weight(height, cumulative_block_weight))
  {
    LOG_ERROR_VER("block weight " << cumulative_block_weight << " is bigger than allowed for this blockchain");
    return false;
  }
  base_reward = get_block_reward();
  if(base_reward + fee < money_in_use)
  {
    LOG_ERROR_VER("coinbase transaction spend too much money (" << print_money(money_in_use) << "). Block reward is " << print_money(base_reward + fee) << "(" << print_money(base_reward) << "+" << print_money(fee) << "), cumulative_block_weight " << cumulative_block_weight);
    return false;
  }
  // From hard fork 2 till 12, we allow a miner to claim less block reward than is allowed, in case a miner wants less dust
  if(base_reward + fee != money_in_use)
  {
    LOG_DEBUG("coinbase transaction doesn't use full amount of block reward:  spent: " << money_in_use << ",  block reward " << base_reward + fee << "(" << base_reward << "+" << fee << ")");
    return false;
  }
  return true;
}
//------------------------------------------------------------------
//TODO: This function only needed minor modification to work with BlockchainDB,
//      and *works*.  As such, to reduce the number of things that might break
//      in moving to BlockchainDB, this function will remain otherwise
//      unchanged for the time being.
//
// This function makes a new block for a miner to mine the hash for
//
// FIXME: this codebase references #if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
// in a lot of places.  That flag is not referenced in any of the code
// nor any of the makefiles, howeve.  Need to look into whether or not it's
// necessary at all.
bool Blockchain::create_block_template(block& b, const crypto::hash *from_block, const spend_view_public_keys& miner_address, diff_t& diffic, uint64_t& height, uint64_t& expected_reward, const string_blob& ex_nonce)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  uint64_t pool_cookie;

  m_tx_pool.lock();
  const auto unlock_guard = epee::misc_utils::create_scope_leave_handler([&]() { m_tx_pool.unlock(); });
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  if (m_btc_valid && !from_block) {
    // The pool cookie is atomic. The lack of locking is OK, as if it changes
    // just as we compare it, we'll just use a slightly old template, but
    // this would be the case anyway if we'd lock, and the change happened
    // just after the block template was created
    if (!memcmp(&miner_address, &m_btc_address, sizeof(cryptonote::spend_view_public_keys)) && m_btc_nonce == ex_nonce
      && m_btc_pool_cookie == m_tx_pool.cookie() && m_btc.prev_id == get_tail_id()) {
      LOG_DEBUG("Using cached template");
      const uint64_t now = time(NULL);
      if (m_btc.timestamp < now) // ensures it can't get below the median of the last few blocks
        m_btc.timestamp = now;
      b = m_btc;
      diffic = m_btc_difficulty;
      height = m_btc_height;
      expected_reward = m_btc_expected_reward;
      return true;
    }
    LOG_DEBUG("Not using cached template: address " << (!memcmp(&miner_address, &m_btc_address, sizeof(cryptonote::spend_view_public_keys))) << ", nonce " << (m_btc_nonce == ex_nonce) << ", cookie " << (m_btc_pool_cookie == m_tx_pool.cookie()) << ", from_block " << (!!from_block));
    invalidate_block_template_cache();
  }

  if (from_block)
  {
    //build alternative subchain, front -> mainchain, back -> alternative head
    //block is not related with head of main chain
    //first of all - look in alternative chains container
    const auto maybe_parent_in_alt = m_db->get_alt_block(*from_block);
    bool parent_in_main = m_db->block_exists(*from_block);
    if (!maybe_parent_in_alt && !parent_in_main)
    {
      LOG_ERROR("Unknown from block");
      return false;
    }
    const alt_block_data_t prev_data = maybe_parent_in_alt->first;

    //we have new block in alternative chain
    std::list<block_extended_info> alt_chain;
    block_verification_context bvc = {};
    std::vector<uint64_t> timestamps;
    if (!build_alt_chain(*from_block, alt_chain, timestamps, bvc))
      return false;

    if (parent_in_main)
    {
      cryptonote::block prev_block;
      LOG_ERROR_AND_RETURN_UNLESS(get_block_by_hash(*from_block, prev_block), false, "From block not found"); // TODO
      uint64_t from_block_height = cryptonote::get_block_height(prev_block);
      height = from_block_height + 1;
    }
    else
    {
      height = alt_chain.back().height + 1;
    }
    b.major_version = config::lol::constant_hf_version;
    b.minor_version = config::lol::constant_hf_version;
    b.prev_id = *from_block;

    // FIXME: consider moving away from block_extended_info at some point
    block_extended_info bei = {};
    bei.bl = b;
    bei.height = alt_chain.size() ? prev_data.height + 1 : m_db->get_block_height(*from_block) + 1;

    diffic = get_next_difficulty_for_alternative_chain(alt_chain, bei);
  }
  else
  {
    height = m_db->height();
    b.major_version = config::lol::constant_hf_version;
    b.minor_version = config::lol::constant_hf_version;
    b.prev_id = get_tail_id();
    diffic = get_difficulty_for_next_block();
  }
  b.timestamp = time(NULL);

  uint64_t median_ts;
  if (!check_block_timestamp(b, median_ts))
  {
    b.timestamp = median_ts;
  }

  LOG_ERROR_AND_RETURN_UNLESS(diffic, false, "difficulty overhead.");

  size_t txs_weight;
  uint64_t fee;
  if (!m_tx_pool.fill_block_template(height, b, txs_weight, fee, expected_reward))
  {
    return false;
  }
  pool_cookie = m_tx_pool.cookie();
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
  size_t real_txs_weight = 0;
  uint64_t real_fee = 0;
  for(crypto::hash &cur_hash: b.tx_hashes)
  {
    auto cur_res = m_tx_pool.m_transactions.find(cur_hash);
    if (cur_res == m_tx_pool.m_transactions.end())
    {
      LOG_ERROR("Creating block template: error: transaction not found");
      continue;
    }
    tx_memory_pool::tx_details &cur_tx = cur_res->second;
    real_txs_weight += cur_tx.weight;
    real_fee += cur_tx.fee;
    if (cur_tx.weight != get_transaction_weight(cur_tx.tx))
    {
      LOG_ERROR("Creating block template: error: invalid transaction weight");
    }
    if (cur_tx.tx.version == 1)
    {
      uint64_t inputs_amount;
      if (!get_inputs_money_amount(cur_tx.tx, inputs_amount))
      {
        LOG_ERROR("Creating block template: error: cannot get inputs amount");
      }
      else if (cur_tx.fee != inputs_amount - get_tx_outputs_money_amount(cur_tx.tx))
      {
        LOG_ERROR("Creating block template: error: invalid fee");
      }
    }
    else
    {
      if (cur_tx.fee != cur_tx.tx.ringct.fee)
      {
        LOG_ERROR("Creating block template: error: invalid fee");
      }
    }
  }
  if (txs_weight != real_txs_weight)
  {
    LOG_ERROR("Creating block template: error: wrongly calculated transaction weight");
  }
  if (fee != real_fee)
  {
    LOG_ERROR("Creating block template: error: wrongly calculated fee");
  }
  LOG_DEBUG("Creating block template: height " << height <<
      ", transaction weight " << txs_weight <<
      ", fee " << fee);
#endif

  /*
   two-phase miner transaction generation: we don't know exact block weight until we prepare block, but we don't know reward until we know
   block weight, so first miner transaction generated with fake amount of money, and with phase we know think we know expected block weight
   */
  //make blocks coin-base tx looks close to real coinbase tx to get truthful blob weight
  // FIXME: max_outs of miner_tx for lol should be 32?
  const auto miner_tx_no_coinbase_weight =
    construct_miner_tx(height, txs_weight, fee, miner_address);

  LOG_ERROR_AND_RETURN_UNLESS(miner_tx_no_coinbase_weight, false, "Failed to construct miner tx, first chance");

  b.miner_tx = *miner_tx_no_coinbase_weight;

  size_t cumulative_weight = txs_weight + get_transaction_weight(b.miner_tx);

  // FIXME: why loop 10 times here?
  for (size_t try_count = 0; try_count != 10; ++try_count)
  {
    const auto miner_tx =
      construct_miner_tx(height, cumulative_weight, fee, miner_address);

    LOG_ERROR_AND_RETURN_UNLESS(miner_tx, false, "Failed to construct miner tx, second chance");

    b.miner_tx = *miner_tx;

    size_t coinbase_weight = get_transaction_weight(b.miner_tx);
    if (coinbase_weight > cumulative_weight - txs_weight)
    {
      cumulative_weight = txs_weight + coinbase_weight;
      continue;
    }

    if (coinbase_weight < cumulative_weight - txs_weight)
    {
      size_t delta = cumulative_weight - txs_weight - coinbase_weight;
      b.miner_tx.extra.insert(b.miner_tx.extra.end(), delta, 0);
      //here  could be 1 byte difference, because of extra field counter is varint, and it can become from 1-byte len to 2-bytes len.
      if (cumulative_weight != txs_weight + get_transaction_weight(b.miner_tx))
      {
        LOG_ERROR_AND_RETURN_UNLESS(cumulative_weight + 1 == txs_weight + get_transaction_weight(b.miner_tx), false, "unexpected case: cumulative_weight=" << cumulative_weight << " + 1 is not equal txs_cumulative_weight=" << txs_weight << " + get_transaction_weight(b.miner_tx)=" << get_transaction_weight(b.miner_tx));
        b.miner_tx.extra.resize(b.miner_tx.extra.size() - 1);
        if (cumulative_weight != txs_weight + get_transaction_weight(b.miner_tx))
        {
          //fuck, not lucky, -1 makes varint-counter size smaller, in that case we continue to grow with cumulative_weight
          LOG_DEBUG("Miner tx creation has no luck with delta_extra size = " << delta << " and " << delta - 1);
          cumulative_weight += delta - 1;
          continue;
        }
        LOG_DEBUG("Setting extra for block: " << b.miner_tx.extra.size() << ", try_count=" << try_count);
      }
    }
    LOG_ERROR_AND_RETURN_UNLESS(cumulative_weight == txs_weight + get_transaction_weight(b.miner_tx), false, "unexpected case: cumulative_weight=" << cumulative_weight << " is not equal txs_cumulative_weight=" << txs_weight << " + get_transaction_weight(b.miner_tx)=" << get_transaction_weight(b.miner_tx));

    if (!from_block)
      cache_block_template(b, miner_address, ex_nonce, diffic, height, expected_reward, pool_cookie);
    return true;
  }
  LOG_ERROR("Failed to create_block_template with " << 10 << " tries");
  return false;
}
//------------------------------------------------------------------
bool Blockchain::create_block_template(block& b, const spend_view_public_keys& miner_address, diff_t& diffic, uint64_t& height, uint64_t& expected_reward, const string_blob& ex_nonce)
{
  return create_block_template(b, NULL, miner_address, diffic, height, expected_reward, ex_nonce);
}
//------------------------------------------------------------------
// for an alternate chain, get the timestamps from the main chain to complete
// the needed number of timestamps for the BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW.
bool Blockchain::complete_timestamps_vector(uint64_t start_top_height, std::vector<uint64_t>& timestamps) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  size_t blockchain_timestamp_check_window = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2;
  if(timestamps.size() >= blockchain_timestamp_check_window)
    return true;

  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  size_t need_elements = blockchain_timestamp_check_window - timestamps.size();
  LOG_ERROR_AND_RETURN_UNLESS(start_top_height < m_db->height(), false, "internal error: passed start_height not < " << " m_db->height() -- " << start_top_height << " >= " << m_db->height());
  size_t stop_offset = start_top_height > need_elements ? start_top_height - need_elements : 0;
  timestamps.reserve(timestamps.size() + start_top_height - stop_offset);
  while (start_top_height != stop_offset)
  {
    timestamps.push_back(m_db->get_block_timestamp(start_top_height));
    --start_top_height;
  }
  return true;
}
//------------------------------------------------------------------
bool Blockchain::build_alt_chain(const crypto::hash &prev_id, std::list<block_extended_info>& alt_chain, std::vector<uint64_t> &timestamps, block_verification_context& bvc) const
{
    //build alternative subchain, front -> mainchain, back -> alternative head
    timestamps.clear();
    auto maybeAlt = m_db->get_alt_block(prev_id);
    while(maybeAlt)
    {
      const auto& [data, blob] = *maybeAlt;
      block_extended_info bei;
      const auto maybeBlock = maybe_block_from_blob(blob);
      LOG_ERROR_AND_RETURN_UNLESS(maybeBlock, false, "Failed to parse alt block");
      bei.bl = *maybeBlock;
      bei.height = data.height;
      bei.block_cumulative_weight = data.cumulative_weight;
      bei.cumulative_difficulty = data.cumulative_difficulty_high;
      bei.cumulative_difficulty = (bei.cumulative_difficulty << 64) + data.cumulative_difficulty_low;
      bei.already_generated_coins = data.already_generated_coins;
      timestamps.push_back(bei.bl.timestamp);
      alt_chain.push_front(std::move(bei));
      maybeAlt = m_db->get_alt_block(bei.bl.prev_id);
    }

    // if block to be added connects to known blocks that aren't part of the
    // main chain -- that is, if we're adding on to an alternate chain
    if(!alt_chain.empty())
    {
      // make sure alt chain doesn't somehow start past the end of the main chain
      LOG_ERROR_AND_RETURN_UNLESS(m_db->height() > alt_chain.front().height, false, "main blockchain wrong height");

      // make sure that the blockchain contains the block that should connect
      // this alternate chain with it.
      if (!m_db->block_exists(alt_chain.front().bl.prev_id))
      {
        LOG_ERROR("alternate chain does not appear to connect to main chain...");
        return false;
      }

      // make sure block connects correctly to the main chain
      auto h = m_db->get_block_hash_from_height(alt_chain.front().height - 1);
      LOG_ERROR_AND_RETURN_UNLESS(h == alt_chain.front().bl.prev_id, false, "alternative chain has wrong connection to main chain");
      complete_timestamps_vector(m_db->get_block_height(alt_chain.front().bl.prev_id), timestamps);
    }
    // if block not associated with known alternate chain
    else
    {
      // if block parent is not part of main chain or an alternate chain,
      // we ignore it
      bool parent_in_main = m_db->block_exists(prev_id);
      LOG_ERROR_AND_RETURN_UNLESS(parent_in_main, false, "internal error: broken imperative condition: parent_in_main");

      complete_timestamps_vector(m_db->get_block_height(prev_id), timestamps);
    }

    return true;
}
//------------------------------------------------------------------
// If a block is to be added and its parent block is not the current
// main chain top block, then we need to see if we know about its parent block.
// If its parent block is part of a known forked chain, then we need to see
// if that chain is long enough to become the main chain and re-org accordingly
// if so.  If not, we need to hang on to the block in case it becomes part of
// a long forked chain eventually.
bool Blockchain::handle_alternative_block(const block& b, const crypto::hash& id, block_verification_context& bvc)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  m_timestamps_and_difficulties_height = 0;
  m_reset_timestamps_and_difficulties_height = true;
  uint64_t block_height = get_block_height(b);
  if(0 == block_height)
  {
    LOG_ERROR_VER("Block with id: " << epee::string_tools::pod_to_hex(id) << " (as alternative), but miner tx says height is 0.");
    bvc.m_verifivation_failed = true;
    return false;
  }

  //block is not related with head of main chain
  //first of all - look in alternative chains container
  alt_block_data_t prev_data;
  const auto maybe_parent_in_alt = m_db->get_alt_block(b.prev_id);
  if (maybe_parent_in_alt) {
    prev_data = maybe_parent_in_alt->first;
  }
  bool parent_in_main = m_db->block_exists(b.prev_id);
  if (maybe_parent_in_alt || parent_in_main)
  {
    //we have new block in alternative chain
    std::list<block_extended_info> alt_chain;
    std::vector<uint64_t> timestamps;
    if (!build_alt_chain(b.prev_id, alt_chain, timestamps, bvc))
      return false;

    // FIXME: consider moving away from block_extended_info at some point
    block_extended_info bei = {};
    bei.bl = b;
    const uint64_t prev_height = alt_chain.size() ? prev_data.height : m_db->get_block_height(b.prev_id);
    bei.height = prev_height + 1;
    uint64_t block_reward = get_tx_outputs_money_amount(b.miner_tx);
    const uint64_t prev_generated_coins = alt_chain.size() ? prev_data.already_generated_coins : m_db->get_block_already_generated_coins(prev_height);
    bei.already_generated_coins = (block_reward < (MONEY_SUPPLY - prev_generated_coins)) ? prev_generated_coins + block_reward : MONEY_SUPPLY;

    // verify that the block's timestamp is within the acceptable range
    // (not earlier than the median of the last X blocks)
    if(!check_block_timestamp(timestamps, b))
    {
      LOG_ERROR_VER("Block with id: " << id << std::endl << " for alternative chain, has invalid timestamp: " << b.timestamp);
      bvc.m_verifivation_failed = true;
      return false;
    }

    // Check the block's hash against the difficulty target for its alt chain
    diff_t current_diff = get_next_difficulty_for_alternative_chain(alt_chain, bei);
    LOG_ERROR_AND_RETURN_UNLESS(current_diff, false, "!!!!!!! DIFFICULTY OVERHEAD !!!!!!!");
    crypto::hash proof_of_work = {{0xff}};
    {
      proof_of_work = get_mining_hash(bei.bl);
    }
    if(!check_hash(proof_of_work, current_diff))
    {
      LOG_ERROR_VER("Block with id: " << id << std::endl << " for alternative chain, does not have enough proof of work: " << proof_of_work << std::endl << " expected difficulty: " << current_diff);
      bvc.m_verifivation_failed = true;
      bvc.m_bad_pow = true;
      return false;
    }

    if(!prevalidate_miner_transaction(b, bei.height))
    {
      LOG_ERROR_VER("Block with id: " << epee::string_tools::pod_to_hex(id) << " (as alternative) has incorrect miner transaction.");
      bvc.m_verifivation_failed = true;
      return false;
    }

    // FIXME:
    // this brings up an interesting point: consider allowing to get block
    // difficulty both by height OR by hash, not just height.
    const auto current_height = m_db->height() - 1;
    diff_t main_chain_cumulative_difficulty = m_db->get_block_cumulative_difficulty(current_height);

    if (alt_chain.size())
    {
      bei.cumulative_difficulty = prev_data.cumulative_difficulty_high;
      bei.cumulative_difficulty = (bei.cumulative_difficulty << 64) + prev_data.cumulative_difficulty_low;
    }
    else
    {
      // passed-in block's previous block's cumulative difficulty, found on the main chain
      bei.cumulative_difficulty = m_db->get_block_cumulative_difficulty(m_db->get_block_height(b.prev_id));
    }
    bei.cumulative_difficulty += current_diff;

    bei.block_cumulative_weight = cryptonote::get_transaction_weight(b.miner_tx);
    for (const crypto::hash &txid: b.tx_hashes)
    {
      cryptonote::tx_memory_pool::tx_details td;
      cryptonote::string_blob blob;
      if (m_tx_pool.have_tx(txid, relay_category::legacy))
      {
        if (m_tx_pool.get_transaction_info(txid, td))
        {
          bei.block_cumulative_weight += td.weight;
        }
        else
        {
          LOG_ERROR_VER("Transaction is in the txpool, but metadata not found");
          bvc.m_verifivation_failed = true;
          return false;
        }
      }
      else if (m_db->get_tx_blob(txid, blob))
      {
        const auto maybeTx = cryptonote::maybe_tx_from_blob(blob);
        if (!maybeTx)
        {
          LOG_ERROR_VER("Block with id: " << epee::string_tools::pod_to_hex(id) << " (as alternative) refers to unparsable transaction hash " << txid << ".");
          bvc.m_verifivation_failed = true;
          return false;
        }
        bei.block_cumulative_weight += cryptonote::get_transaction_weight(*maybeTx);
      }
      else
      {
        // we can't determine the block weight, set it to 0 and break out of the loop
        bei.block_cumulative_weight = 0;
        break;
      }
    }

    // add block to alternate blocks storage,
    // as well as the current "alt chain" container
    const auto maybeAlt = m_db->get_alt_block(b.prev_id);
    LOG_ERROR_AND_RETURN_UNLESS(!maybeAlt, false, "insertion of new alternative block returned as it already exists");
    cryptonote::alt_block_data_t data;
    data.height = bei.height;
    data.cumulative_weight = bei.block_cumulative_weight;
    data.cumulative_difficulty_low = (bei.cumulative_difficulty & 0xffffffffffffffff).convert_to<uint64_t>();
    data.cumulative_difficulty_high = ((bei.cumulative_difficulty >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
    data.already_generated_coins = bei.already_generated_coins;
    m_db->add_alt_block(id, data, cryptonote::block_to_blob(bei.bl));
    alt_chain.push_back(bei);

    if(main_chain_cumulative_difficulty < bei.cumulative_difficulty) //check if difficulty bigger then in main chain
    {
      //do reorganize!
      LOG_GLOBAL_INFO_GREEN
        (
         std::endl
         << config::lol::hash_sep << "REORGANIZE" << std::endl
         << std::endl
         << "OLD" << std::endl
         << config::lol::tab_sep << "height:         " << current_height << std::endl
         << config::lol::tab_sep << "∑ difficulty:   " << main_chain_cumulative_difficulty << std::endl
         << std::endl
         << "NEW" << std::endl
         << config::lol::tab_sep << "height:         " << bei.height << std::endl
         << config::lol::tab_sep << "∑ difficulty:   " << bei.cumulative_difficulty << std::endl
         << config::lol::tab_sep << "id:             " << id << std::endl
         << config::lol::tab_sep << "PoW:            " << proof_of_work << std::endl
         << config::lol::tab_sep << "difficulty:     " << current_diff << std::endl
         << config::lol::tab_sep << "new blocks:     " << alt_chain.size() << std::endl
         );

      bool r = switch_to_alternative_blockchain(alt_chain, false);
      if (r)
        bvc.m_added_to_main_chain = true;
      else
        bvc.m_verifivation_failed = true;
      return r;
    }
    else
    {
      LOG_GLOBAL_INFO_BLUE
        (
         std::endl
         << config::lol::dash_sep << "BLOCK ADDED AS ALTERNATIVE" << std::endl
         << std::endl
         << "CURRENT" << std::endl
         << config::lol::tab_sep << "height:         " << current_height << std::endl
         << config::lol::tab_sep << "∑ difficulty:   " << main_chain_cumulative_difficulty << std::endl
         << std::endl
         << "ALTERNATIVE" << std::endl
         << config::lol::tab_sep << "height:         " << bei.height << std::endl
         << config::lol::tab_sep << "∑ difficulty:   " << bei.cumulative_difficulty << std::endl
         << config::lol::tab_sep << "id:             " << id << std::endl
         << config::lol::tab_sep << "PoW:            " << proof_of_work << std::endl
         << config::lol::tab_sep << "difficulty:     " << current_diff << std::endl
         );
      return true;
    }
  }
  else
  {
    //block orphaned
    bvc.m_marked_as_orphaned = true;
    LOG_VERBOSE
      (
       std::endl
       << config::lol::x_sep << "Block recognized as orphaned and rejected" << std::endl
       << std::endl
       << "CURRENT" << std::endl
       << config::lol::tab_sep << "height:         " << get_current_blockchain_height() << std::endl
       << config::lol::tab_sep << "top:            " << get_tail_id() << std::endl
       << std::endl
       << "ORPHANED" << std::endl
       << config::lol::tab_sep << "height:         " << block_height << std::endl
       << config::lol::tab_sep << "id:             " << id << std::endl
       << config::lol::tab_sep << "parent:         " << b.prev_id << std::endl
       << config::lol::tab_sep << "parent in alt:  " << (bool)maybe_parent_in_alt << std::endl
       << config::lol::tab_sep << "parent in main: " << parent_in_main << std::endl
       );
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_blocks(uint64_t start_offset, size_t count, std::vector<std::pair<cryptonote::string_blob,block>>& blocks, std::vector<cryptonote::string_blob>& txs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  if(start_offset >= m_db->height())
    return false;

  if (!get_blocks(start_offset, count, blocks))
  {
    return false;
  }

  for(const auto& blk : blocks)
  {
    std::vector<crypto::hash> missed_ids;
    get_transactions_blobs(blk.second.tx_hashes, txs, missed_ids);
    LOG_ERROR_AND_RETURN_UNLESS(!missed_ids.size(), false, "has missed transactions in own block in main blockchain");
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_blocks(uint64_t start_offset, size_t count, std::vector<std::pair<cryptonote::string_blob,block>>& blocks) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  const uint64_t height = m_db->height();
  if(start_offset >= height)
    return false;

  blocks.reserve(blocks.size() + height - start_offset);
  for(size_t i = start_offset; i < start_offset + count && i < height;i++)
  {
    blocks.push_back(std::make_pair(m_db->get_block_blob_from_height(i), block()));
    const auto maybeBlock = maybe_block_from_blob(blocks.back().first);
    if (!maybeBlock)
    {
      LOG_ERROR("Invalid block");
      return false;
    }
    blocks.back().second = *maybeBlock;
  }
  return true;
}
//------------------------------------------------------------------
//TODO: This function *looks* like it won't need to be rewritten
//      to use BlockchainDB, as it calls other functions that were,
//      but it warrants some looking into later.
//
//FIXME: This function appears to want to return false if any transactions
//       that belong with blocks are missing, but not if blocks themselves
//       are missing.
bool Blockchain::handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS::request& arg, NOTIFY_RESPONSE_GET_OBJECTS::request& rsp)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  db_rtxn_guard rtxn_guard (m_db);
  rsp.current_blockchain_height = get_current_blockchain_height();
  std::vector<std::pair<cryptonote::string_blob,block>> blocks;
  get_blocks(arg.blocks, blocks, rsp.missed_ids);

  for (size_t i = 0; i < blocks.size(); ++i)
  {
    auto& bl = blocks[i];
    std::vector<crypto::hash> missed_tx_ids;

    rsp.blocks.push_back(block_complete_entry());
    block_complete_entry& e = rsp.blocks.back();

    // FIXME: s/rsp.missed_ids/missed_tx_id/ ?  Seems like rsp.missed_ids
    //        is for missed blocks, not missed transactions as well.
    e.pruned = arg.prune;
    get_transactions_blobs(bl.second.tx_hashes, e.txs, missed_tx_ids);
    if (missed_tx_ids.size() != 0)
    {
      // append missed transaction hashes to response missed_ids field,
      // as done below if any standalone transactions were requested
      // and missed.
      rsp.missed_ids.insert(rsp.missed_ids.end(), missed_tx_ids.begin(), missed_tx_ids.end());
      return false;
    }

    //pack block
    e.block = std::move(bl.first);
    e.block_weight = 0;
    if (arg.prune && m_db->block_exists(arg.blocks[i]))
      e.block_weight = m_db->get_block_weight(m_db->get_block_height(arg.blocks[i]));
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_alternative_blocks(std::vector<block>& blocks) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);

  blocks.reserve(m_db->get_alt_block_count());
  m_db->for_all_alt_blocks
    ([&blocks]
     (const crypto::hash &blkid
      , const cryptonote::alt_block_data_t &data
      , const cryptonote::string_blob_view blob
      ) {
    const auto maybeBlock = maybe_block_from_blob(blob);
    if (maybeBlock) {
      blocks.push_back(*maybeBlock);
    }
    else {
      LOG_ERROR("Failed to parse block from blob");
    }
    return true;
  });
  return true;
}
//------------------------------------------------------------------
size_t Blockchain::get_alternative_blocks_count() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  return m_db->get_alt_block_count();
}
//------------------------------------------------------------------
// This function adds the output specified by <amount, i> to the result_outs container
// unlocked and other such checks should be done by here.
uint64_t Blockchain::get_num_mature_outputs(uint64_t amount) const
{
  uint64_t num_outs = m_db->get_num_outputs(amount);
  // ensure we don't include outputs that aren't yet eligible to be used
  // outpouts are sorted by height
  const uint64_t blockchain_height = m_db->height();
  while (num_outs > 0)
  {
    const tx_out_index toi = m_db->get_output_tx_and_index(amount, num_outs - 1);
    const uint64_t height = m_db->get_tx_block_height(toi.first);
    if (height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE <= blockchain_height)
      break;
    --num_outs;
  }

  return num_outs;
}

crypto::public_key Blockchain::get_output_key(uint64_t amount, uint64_t global_index) const
{
  output_data_t data = m_db->get_output_key(amount, global_index);
  return data.pubkey;
}

//------------------------------------------------------------------
bool Blockchain::get_tx_outputs(const COMMAND_RPC_GET_OUTPUTS_BIN::request& req, COMMAND_RPC_GET_OUTPUTS_BIN::response& res) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);

  res.outs.clear();
  res.outs.reserve(req.outputs.size());

  std::vector<cryptonote::output_data_t> data;
  try
  {
    std::vector<uint64_t> amounts, offsets;
    amounts.reserve(req.outputs.size());
    offsets.reserve(req.outputs.size());
    for (const auto &i: req.outputs)
    {
      amounts.push_back(i.amount);
      offsets.push_back(i.index);
    }
    m_db->get_output_key(std::span<const uint64_t>(amounts.data(), amounts.size()), offsets, data);
    if (data.size() != req.outputs.size())
    {
      LOG_ERROR("Unexpected output data size: expected " << req.outputs.size() << ", got " << data.size());
      return false;
    }
    for (const auto &t: data)
      res.outs.push_back({t.pubkey, t.commitment, is_tx_spendtime_unlocked(t.unlock_time), t.height, crypto::null_hash});

    if (req.get_txid)
    {
      for (size_t i = 0; i < req.outputs.size(); ++i)
      {
        tx_out_index toi = m_db->get_output_tx_and_index(req.outputs[i].amount, req.outputs[i].index);
        res.outs[i].txid = toi.first;
      }
    }
  }
  catch (const std::exception &e)
  {
    return false;
  }
  return true;
}
//------------------------------------------------------------------
void Blockchain::get_output_key_mask_unlocked(const uint64_t& amount, const uint64_t& index, crypto::public_key& key, rct::rct_point& mask, bool& unlocked) const
{
  const auto o_data = m_db->get_output_key(amount, index);
  key = o_data.pubkey;
  mask = o_data.commitment;
  tx_out_index toi = m_db->get_output_tx_and_index(amount, index);
  unlocked = is_tx_spendtime_unlocked(m_db->get_tx_unlock_time(toi.first));
}
//------------------------------------------------------------------
bool Blockchain::get_output_distribution(uint64_t amount, uint64_t from_height, uint64_t to_height, uint64_t &start_height, std::vector<uint64_t> &distribution, uint64_t &base) const
{
  start_height = 0;
  base = 0;

  if (to_height > 0 && to_height < from_height)
    return false;

  if (from_height > start_height)
    start_height = from_height;

  distribution.clear();
  uint64_t db_height = m_db->height();
  if (db_height == 0)
    return false;
  if (start_height >= db_height || to_height >= db_height)
    return false;
  if (amount == 0)
  {
    std::vector<uint64_t> heights;
    heights.reserve(to_height + 1 - start_height);
    const uint64_t real_start_height = start_height > 0 ? start_height-1 : start_height;
    for (uint64_t h = real_start_height; h <= to_height; ++h)
      heights.push_back(h);
    distribution = m_db->get_block_cumulative_rct_outputs(heights);
    if (start_height > 0)
    {
      base = distribution[0];
      distribution.erase(distribution.begin());
    }
    return true;
  }
  else
  {
    return m_db->get_output_distribution(amount, start_height, to_height, distribution, base);
  }
}
//------------------------------------------------------------------
// This function takes a list of block hashes from another node
// on the network to find where the split point is between us and them.
// This is used to see what to send another node that needs to sync.
bool Blockchain::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, uint64_t& starter_offset) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);

  // make sure the request includes at least the genesis block, otherwise
  // how can we expect to sync from the client that the block list came from?
  if(qblock_ids.empty())
  {
    LOG_CATEGORY_ERROR("net.p2p", "Client sent wrong NOTIFY_REQUEST_CHAIN: m_block_ids.size()=" << qblock_ids.size() << ", dropping connection");
    return false;
  }

  db_rtxn_guard rtxn_guard(m_db);
  // make sure that the last block in the request's block list matches
  // the genesis block
  auto gen_hash = m_db->get_block_hash_from_height(0);
  if(qblock_ids.back() != gen_hash)
  {
    LOG_CATEGORY_ERROR("net.p2p", "Client sent wrong NOTIFY_REQUEST_CHAIN: genesis block mismatch: " << std::endl << "id: " << qblock_ids.back() << ", " << std::endl << "expected: " << gen_hash << "," << std::endl << " dropping connection");
    return false;
  }

  // Find the first block the foreign chain has that we also have.
  // Assume qblock_ids is in reverse-chronological order.
  auto bl_it = qblock_ids.begin();
  uint64_t split_height = 0;
  for(; bl_it != qblock_ids.end(); bl_it++)
  {
    try
    {
      if (m_db->block_exists(*bl_it, &split_height))
        break;
    }
    catch (const std::exception& e)
    {
      LOG_WARNING("Non-critical error trying to find block by hash in BlockchainDB, hash: " << *bl_it);
      return false;
    }
  }

  // this should be impossible, as we checked that we share the genesis block,
  // but just in case...
  if(bl_it == qblock_ids.end())
  {
    LOG_ERROR("Internal error handling connection, can't find split point");
    return false;
  }

  //we start to put block ids INCLUDING last known id, just to make other side be sure
  starter_offset = split_height;
  return true;
}
//------------------------------------------------------------------
diff_t Blockchain::block_difficulty(uint64_t i) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  try
  {
    return m_db->get_block_difficulty(i);
  }
  catch (const BLOCK_DNE& e)
  {
    LOG_ERROR("Attempted to get block difficulty for height above blockchain height");
  }
  return 0;
}
//------------------------------------------------------------------
template<typename T> void reserve_container(std::vector<T> &v, size_t N) { v.reserve(N); }
template<typename T> void reserve_container(std::list<T> &v, size_t N) { }
//------------------------------------------------------------------
//TODO: return type should be void, throw on exception
//       alternatively, return true only if no blocks missed
template<class t_ids_container, class t_blocks_container, class t_missed_container>
bool Blockchain::get_blocks(const t_ids_container& block_ids, t_blocks_container& blocks, t_missed_container& missed_bs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);

  reserve_container(blocks, block_ids.size());
  for (const auto& block_hash : block_ids)
  {
    try
    {
      uint64_t height = 0;
      if (m_db->block_exists(block_hash, &height))
      {
        blocks.push_back(std::make_pair(m_db->get_block_blob_from_height(height), block()));
        const auto maybeBlock = maybe_block_from_blob(blocks.back().first);
        if (!maybeBlock)
        {
          LOG_ERROR("Invalid block: " << block_hash);
          blocks.pop_back();
          missed_bs.push_back(block_hash);
        }
        blocks.back().second = *maybeBlock;
      }
      else
        missed_bs.push_back(block_hash);
    }
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
static bool fill(BlockchainDB *db, const crypto::hash &tx_hash, cryptonote::string_blob &tx)
{
  {
    if (!db->get_tx_blob(tx_hash, tx))
    {
      LOG_DEBUG("Transaction blob not found for " << tx_hash);
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
static bool fill(BlockchainDB *db, const crypto::hash &tx_hash, tx_blob_entry &tx)
{
  if (!fill(db, tx_hash, tx.blob))
    return false;
  return true;
}
//------------------------------------------------------------------
//TODO: return type should be void, throw on exception
//       alternatively, return true only if no transactions missed
bool Blockchain::get_transactions_blobs(const std::span<const crypto::hash> txs_ids, std::vector<cryptonote::string_blob>& txs, std::vector<crypto::hash>& missed_txs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);

  txs.reserve(txs_ids.size());
  for (const auto& tx_hash : txs_ids)
  {
    try
    {
      cryptonote::string_blob tx;
      if (fill(m_db, tx_hash, tx))
        txs.push_back(std::move(tx));
      else
        missed_txs.push_back(tx_hash);
    }
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_transactions_blobs(const std::span<const crypto::hash> txs_ids, std::vector<tx_blob_entry>& txs, std::vector<crypto::hash>& missed_txs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);

  txs.reserve(txs_ids.size());
  for (const auto& tx_hash : txs_ids)
  {
    try
    {
      tx_blob_entry tx;
      if (fill(m_db, tx_hash, tx))
        txs.push_back(std::move(tx));
      else
        missed_txs.push_back(tx_hash);
    }
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
size_t get_transaction_version(const cryptonote::string_blob &bd)
{
  size_t version;
  const char* begin = static_cast<const char*>(bd.data());
  const char* end = begin + bd.size();
  int read = tools::read_varint(begin, end, version);
  if (read <= 0)
    throw std::runtime_error("Internal error getting transaction version");
  return version;
}
//------------------------------------------------------------------
template<class t_ids_container, class t_tx_container, class t_missed_container>
bool Blockchain::get_split_transactions_blobs(const t_ids_container txs_ids, t_tx_container& txs, t_missed_container& missed_txs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);

  reserve_container(txs, txs_ids.size());
  for (const auto& tx_hash : txs_ids)
  {
    try
    {
      cryptonote::string_blob tx;
      if (m_db->get_tx_blob(tx_hash, tx))
      {
        txs.push_back(std::make_pair(tx_hash, tx));
      }
      else
        missed_txs.push_back(tx_hash);
    }
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
template<class t_ids_container, class t_tx_container, class t_missed_container>
bool Blockchain::get_transactions(const t_ids_container txs_ids, t_tx_container& txs, t_missed_container& missed_txs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);

  reserve_container(txs, txs_ids.size());
  for (const auto& tx_hash : txs_ids)
  {
    try
    {
      cryptonote::string_blob tx_blob;
      if (m_db->get_tx_blob(tx_hash, tx_blob))
      {
        txs.push_back(transaction());
        const auto maybeTx = maybe_tx_from_blob(tx_blob);
        if (!maybeTx)
        {
          LOG_ERROR("Invalid transaction");
          return false;
        }
        txs.back() = *maybeTx;
      }
      else
        missed_txs.push_back(tx_hash);
    }
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
// Find the split point between us and foreign blockchain and return
// (by reference) the most recent common block hash along with up to
// BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT additional (more recent) hashes.
bool Blockchain::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, std::vector<crypto::hash>& hashes, std::vector<uint64_t>* weights, uint64_t& start_height, uint64_t& current_height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);

  // if we can't find the split point, return false
  if(!find_blockchain_supplement(qblock_ids, start_height))
  {
    return false;
  }

  db_rtxn_guard rtxn_guard(m_db);
  current_height = get_current_blockchain_height();
  uint64_t stop_height = current_height;
  size_t count = 0;
  const size_t reserve = std::min((size_t)(stop_height - start_height), BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT);
  hashes.reserve(reserve);
  if (weights)
    weights->reserve(reserve);
  for(size_t i = start_height; i < stop_height && count < BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT; i++, count++)
  {
    hashes.push_back(m_db->get_block_hash_from_height(i));
    if (weights)
      weights->push_back(m_db->get_block_weight(i));
  }

  return true;
}

bool Blockchain::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, NOTIFY_RESPONSE_CHAIN_ENTRY::request& resp) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);

  bool result = find_blockchain_supplement(qblock_ids, resp.m_block_ids, &resp.m_block_weights, resp.start_height, resp.total_height);
  if (result)
  {
    cryptonote::diff_t wide_cumulative_difficulty = m_db->get_block_cumulative_difficulty(resp.total_height - 1);
    resp.cumulative_difficulty = (wide_cumulative_difficulty & 0xffffffffffffffff).convert_to<uint64_t>();
    resp.cumulative_difficulty_top64 = ((wide_cumulative_difficulty >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
  }

  return result;
}
//------------------------------------------------------------------
//FIXME: change argument to std::vector, low priority
// find split point between ours and foreign blockchain (or start at
// blockchain height <req_start_block>), and return up to max_count FULL
// blocks by reference.
bool Blockchain::find_blockchain_supplement(const uint64_t req_start_block, const std::list<crypto::hash>& qblock_ids, std::vector<std::pair<std::pair<cryptonote::string_blob, crypto::hash>, std::vector<std::pair<crypto::hash, cryptonote::string_blob> > > >& blocks, uint64_t& total_height, uint64_t& start_height, bool get_miner_tx_hash, size_t max_count) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);

  // if a specific start height has been requested
  if(req_start_block > 0)
  {
    // if requested height is higher than our chain, return false -- we can't help
    if (req_start_block >= m_db->height())
    {
      return false;
    }
    start_height = req_start_block;
  }
  else
  {
    if(!find_blockchain_supplement(qblock_ids, start_height))
    {
      return false;
    }
  }

  db_rtxn_guard rtxn_guard(m_db);
  total_height = get_current_blockchain_height();
  blocks.reserve(std::min(std::min(max_count, (size_t)10000), (size_t)(total_height - start_height)));
  LOG_ERROR_AND_RETURN_UNLESS(m_db->get_blocks_from(start_height, 3, max_count, FIND_BLOCKCHAIN_SUPPLEMENT_MAX_SIZE, blocks, true, get_miner_tx_hash),
      false, "Error getting blocks");

  return true;
}
//------------------------------------------------------------------
bool Blockchain::add_block_as_invalid(const block& bl, const crypto::hash& h)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  block_extended_info bei = AUTO_VAL_INIT(bei);
  bei.bl = bl;
  return add_block_as_invalid(bei, h);
}
//------------------------------------------------------------------
bool Blockchain::add_block_as_invalid(const block_extended_info& bei, const crypto::hash& h)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  auto i_res = m_invalid_blocks.insert(std::map<crypto::hash, block_extended_info>::value_type(h, bei));
  LOG_ERROR_AND_RETURN_UNLESS(i_res.second, false, "at insertion invalid by tx returned status existed");
  LOG_INFO("BLOCK ADDED AS INVALID: " << h << std::endl << ", prev_id=" << bei.bl.prev_id << ", m_invalid_blocks count=" << m_invalid_blocks.size());
  return true;
}
//------------------------------------------------------------------
void Blockchain::flush_invalid_blocks()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  m_invalid_blocks.clear();
}
//------------------------------------------------------------------
bool Blockchain::have_block_unlocked(const crypto::hash& id, int *where) const
{
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  LOG_PRINT_L3("Blockchain::" << __func__);

  if(m_db->block_exists(id))
  {
    LOG_PRINT_L2("block " << id << " found in main chain");
    if (where) *where = HAVE_BLOCK_MAIN_CHAIN;
    return true;
  }

  if(m_db->get_alt_block(id))
  {
    LOG_PRINT_L2("block " << id << " found in alternative chains");
    if (where) *where = HAVE_BLOCK_ALT_CHAIN;
    return true;
  }

  if(m_invalid_blocks.count(id))
  {
    LOG_PRINT_L2("block " << id << " found in m_invalid_blocks");
    if (where) *where = HAVE_BLOCK_INVALID;
    return true;
  }

  return false;
}
//------------------------------------------------------------------
bool Blockchain::have_block(const crypto::hash& id, int *where) const
{
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  return have_block_unlocked(id, where);
}
//------------------------------------------------------------------
bool Blockchain::handle_block_to_main_chain(const block& bl, block_verification_context& bvc, bool notify/* = true*/)
{
    LOG_PRINT_L3("Blockchain::" << __func__);
    crypto::hash id = get_block_hash(bl);
    return handle_block_to_main_chain(bl, id, bvc, notify);
}
//------------------------------------------------------------------
size_t Blockchain::get_total_transactions() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
  // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
  // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
  // lock if it is otherwise needed.
  return m_db->get_tx_count();
}
//------------------------------------------------------------------
// This function checks each input in the transaction <tx> to make sure it
// has not been used already, and adds its key to the container <keys_this_block>.
//
// This container should be managed by the code that validates blocks so we don't
// have to store the used keys in a given block in the permanent storage only to
// remove them later if the block fails validation.
bool Blockchain::check_for_double_spend(const transaction& tx, output_spend_public_key_images_container& keys_this_block) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  struct add_transaction_input_visitor: public boost::static_visitor<bool>
  {
    output_spend_public_key_images_container& m_spent_keys;
    BlockchainDB* m_db;
    add_transaction_input_visitor(output_spend_public_key_images_container& spent_keys, BlockchainDB* db) :
      m_spent_keys(spent_keys), m_db(db)
    {
    }
    bool operator()(const txin_to_key& in) const
    {
      const crypto::output_spend_public_key_image& ki = in.output_spend_public_key_image;

      // attempt to insert the newly-spent key into the container of
      // keys spent this block.  If this fails, the key was spent already
      // in this block, return false to flag that a double spend was detected.
      //
      // if the insert into the block-wide spent keys container succeeds,
      // check the blockchain-wide spent keys container and make sure the
      // key wasn't used in another block already.
      auto r = m_spent_keys.insert(ki);
      if(!r.second || m_db->has_output_spend_public_key_image(ki))
      {
        //double spend detected
        return false;
      }

      // if no double-spend detected, return true
      return true;
    }

    bool operator()(const txin_gen& tx) const
    {
      return true;
    }
  };

  for (const txin_v& in : tx.vin)
  {
    if(!boost::apply_visitor(add_transaction_input_visitor(keys_this_block, m_db), in))
    {
      LOG_ERROR("Double spend detected!");
      return false;
    }
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_tx_outputs_gindexs(const crypto::hash& tx_id, size_t n_txes, std::vector<std::vector<uint64_t>>& indexs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  uint64_t tx_index;
  if (!m_db->tx_exists(tx_id, tx_index))
  {
    LOG_ERROR_VER("get_tx_outputs_gindexs failed to find transaction with id = " << tx_id);
    return false;
  }
  indexs = m_db->get_tx_amount_output_indices(tx_index, n_txes);
  LOG_ERROR_AND_RETURN_UNLESS(n_txes == indexs.size(), false, "Wrong indexs size");

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_tx_outputs_gindexs(const crypto::hash& tx_id, std::vector<uint64_t>& indexs) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  uint64_t tx_index;
  if (!m_db->tx_exists(tx_id, tx_index))
  {
    LOG_ERROR_VER("get_tx_outputs_gindexs failed to find transaction with id = " << tx_id);
    return false;
  }
  std::vector<std::vector<uint64_t>> indices = m_db->get_tx_amount_output_indices(tx_index, 1);
  LOG_ERROR_AND_RETURN_UNLESS(indices.size() == 1, false, "Wrong indices size");
  indexs = indices.front();
  return true;
}
//------------------------------------------------------------------
void Blockchain::on_new_tx_from_block(const cryptonote::transaction &tx)
{
}
//------------------------------------------------------------------
//FIXME: it seems this function is meant to be merely a wrapper around
//       another function of the same name, this one adding one bit of
//       functionality.  Should probably move anything more than that
//       (getting the hash of the block at height max_used_block_id)
//       to the other function to keep everything in one place.
// This function overloads its sister function with
// an extra value (hash of highest block that holds an output used as input)
// as a return-by-reference.
bool Blockchain::check_tx_inputs(transaction& tx, uint64_t& max_used_block_height, crypto::hash& max_used_block_id, tx_verification_context &tvc, bool kept_by_block) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);

  TIME_MEASURE_START(a);
  bool res = check_tx_inputs(tx, tvc, &max_used_block_height);
  TIME_MEASURE_FINISH(a);
  if(m_show_time_stats)
  {
    size_t ring_size = !tx.vin.empty() && tx.vin[0].type() == typeid(txin_to_key) ? boost::get<txin_to_key>(tx.vin[0]).output_relative_offsets.size() : 0;
    LOG_INFO("HASH: " <<  get_transaction_hash(tx) << " I/M/O: " << tx.vin.size() << "/" << ring_size << "/" << tx.vout.size() << " H: " << max_used_block_height << " ms: " << a + m_fake_scan_time << " B: " << get_object_blobsize(tx) << " W: " << get_transaction_weight(tx));
  }
  if (!res)
    return false;

  LOG_ERROR_AND_RETURN_UNLESS(max_used_block_height < m_db->height(), false,  "internal error: max used block index=" << max_used_block_height << " is not less then blockchain size = " << m_db->height());
  max_used_block_id = m_db->get_block_hash_from_height(max_used_block_height);
  return true;
}
//------------------------------------------------------------------
bool Blockchain::check_tx_outputs(const transaction& tx, tx_verification_context &tvc) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);

  for (auto &o: tx.vout) {
    if (o.amount != 0) {
      tvc.m_invalid_output = true;
      return false;
    }
  }

  if (tx.ringct.type != rct::RCTTypeCLSAG)
  {
    LOG_ERROR_VER("Ringct type " << (unsigned)tx.ringct.type << " is not allowed");
    tvc.m_invalid_output = true;
    return false;
  }

  if (!check_tx_output_points(tx)) {
    tvc.m_invalid_output = true;
    return false;
  };

  return true;
}
//------------------------------------------------------------------
bool Blockchain::have_tx_keyimges_as_spent(const transaction &tx) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  for (const txin_v& in: tx.vin)
  {
    CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, in_to_key, true);
    if(have_tx_keyimg_as_spent(in_to_key.output_spend_public_key_image))
      return true;
  }
  return false;
}
bool Blockchain::expand_transaction_2(transaction &tx, const crypto::hash &tx_prefix_hash, const std::vector<std::vector<rct::output_public_data>> &pubkeys) const
{
  LOG_ERROR_AND_RETURN_UNLESS(tx.version == 2, false, "Transaction version is not 2");

  rct::rctData &rv = tx.ringct;

  // message - hash of the transaction prefix
  rv.message = tx_prefix_hash;

  // decoys - full and simple store it in opposite ways
  if (rv.type == rct::RCTTypeCLSAG)
  {
    LOG_ERROR_AND_RETURN_UNLESS(!pubkeys.empty() && !pubkeys[0].empty(), false, "empty pubkeys");
    rv.decoys.resize(pubkeys.size());
    for (size_t n = 0; n < pubkeys.size(); ++n)
    {
      rv.decoys[n].clear();
      for (size_t m = 0; m < pubkeys[n].size(); ++m)
      {
        rv.decoys[n].push_back(pubkeys[n][m]);
      }
    }
  }
  else
  {
    LOG_ERROR_AND_RETURN_UNLESS(false, false, "Unsupported rct tx type: " + boost::lexical_cast<std::string>(rv.type));
  }

  // II
  if (rv.type == rct::RCTTypeCLSAG)
  {
      LOG_ERROR_AND_RETURN_UNLESS(rv.p.CLSAGs.size() == tx.vin.size(), false, "Bad CLSAGs size");
      for (size_t n = 0; n < tx.vin.size(); ++n)
      {
        rv.p.CLSAGs[n].signer_pk_image = boost::get<txin_to_key>(tx.vin[n]).output_spend_public_key_image;
      }
  }
  else
  {
    LOG_ERROR_AND_RETURN_UNLESS(false, false, "Unsupported rct tx type: " + boost::lexical_cast<std::string>(rv.type));
  }

  // output_commits was already done by handle_incoming_tx

  return true;
}
//------------------------------------------------------------------
bool Blockchain::check_fee(size_t tx_weight, uint64_t fee) const
{
  uint64_t needed_fee = 0;
  {
    uint64_t fee_per_byte = constant::FEE_PER_BYTE;
    LOG_DEBUG("Using " << print_money(fee_per_byte) << "/byte fee");
    needed_fee = tx_weight * fee_per_byte;
    // quantize fee up to 8 decimals
    const uint64_t mask = constant::fee_quantization_mask;
    needed_fee = (needed_fee + mask - 1) / mask * mask;
  }

  if (fee < needed_fee - needed_fee / 50) // keep a little 2% buffer on acceptance - no integer overflow
  {
    LOG_ERROR_VER("transaction fee is not enough: " << print_money(fee) << ", minimum fee: " << print_money(needed_fee));
    return false;
  }
  return true;
}

//------------------------------------------------------------------
// This function checks to see if a tx is unlocked.  unlock_time is either
// a block index or a unix time.
bool Blockchain::is_tx_spendtime_unlocked(const uint64_t unlock_time) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // ND: Instead of calling get_current_blockchain_height(), call m_db->height()
  //    directly as get_current_blockchain_height() locks the recursive mutex.
  if (unlock_time == 0) return true;
  return m_db->height() + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS > unlock_time;
}
//------------------------------------------------------------------
// This function locates all outputs associated with a given input (mixins)
// and validates that they exist and are usable.  It also checks the ring
// signature for each input.
bool Blockchain::check_tx_input
(
  size_t tx_version
  , const txin_to_key& txin
  , const crypto::hash& tx_prefix_hash
  , const rct::rctData &ringct
  , std::vector<rct::output_public_data> &output_keys
  , uint64_t* pmax_related_block_height
  ) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  // ND:
  // 1. Disable locking and make method private.
  //LOCK_RECURSIVE_MUTEX(m_blockchain_lock);

  struct outputs_visitor
  {
    std::vector<rct::output_public_data >& m_output_keys;
    const Blockchain& m_bch;
    outputs_visitor(std::vector<rct::output_public_data>& output_keys, const Blockchain& bch) :
      m_output_keys(output_keys), m_bch(bch)
    {
    }
    bool handle_output(uint64_t unlock_time, const crypto::public_key &pubkey, const rct::rct_point &commitment)
    {
      //check tx unlock time
      if (!m_bch.is_tx_spendtime_unlocked(unlock_time))
      {
        LOG_ERROR_VER("One of outputs for one of inputs has wrong tx.unlock_time = " << unlock_time);
        return false;
      }

      // The original code includes a check for the output corresponding to this input
      // to be a txout_to_key. This is removed, as the database does not store this info,
      // but only txout_to_key outputs are stored in the DB in the first place, done in
      // Blockchain*::add_output

      m_output_keys.push_back(rct::output_public_data({pubkey, commitment}));
      return true;
    }
  };

  output_keys.clear();

  // collect output keys
  outputs_visitor vi(output_keys, *this);
  if (!scan_outputkeys_for_indexes(tx_version, txin, vi, tx_prefix_hash, pmax_related_block_height))
  {
    LOG_ERROR_VER("Failed to get output keys for tx with amount = " << print_money(txin.amount) << " and count indexes " << txin.output_relative_offsets.size());
    return false;
  }

  if(txin.output_relative_offsets.size() != output_keys.size())
  {
    LOG_ERROR_VER("Output keys for tx with amount = " << txin.amount << " and count indexes " << txin.output_relative_offsets.size() << " returned wrong keys count " << output_keys.size());
    return false;
  }
  // ringct will be expanded after this
  return true;
}
//------------------------------------------------------------------
//TODO: revisit, has changed a bit on upstream
bool Blockchain::check_block_timestamp(std::vector<uint64_t>& timestamps, const block& b, uint64_t& median_ts) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  median_ts = epee::misc_utils::median(timestamps);
  size_t blockchain_timestamp_check_window = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2;
  if(b.timestamp < median_ts)
  {
    LOG_ERROR_VER("Timestamp of block with id: " << get_block_hash(b) << ", " << b.timestamp << ", less than median of last " << blockchain_timestamp_check_window << " blocks, " << median_ts);
    return false;
  }

  return true;
}
//------------------------------------------------------------------
// This function grabs the timestamps from the most recent <n> blocks,
// where n = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW.  If there are not those many
// blocks in the blockchain, the timestap is assumed to be valid.  If there
// are, this function returns:
//   true if the block's timestamp is not less than the timestamp of the
//       median of the selected blocks
//   false otherwise
bool Blockchain::check_block_timestamp(const block& b, uint64_t& median_ts) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  uint64_t cryptonote_block_future_time_limit = CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V2;
  size_t blockchain_timestamp_check_window = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2;

  if(b.timestamp > (uint64_t)time(NULL) + cryptonote_block_future_time_limit)
  {
    LOG_ERROR_VER("Timestamp of block with id: " << get_block_hash(b) << ", " << b.timestamp << ", bigger than local time + 10 minutes");
    return false;
  }

  const auto h = m_db->height();

  // if not enough blocks, no proper median yet, return true
  if(h < blockchain_timestamp_check_window)
  {
    return true;
  }

  std::vector<uint64_t> timestamps;

  // need most recent 60 blocks, get index of first of those
  size_t offset = h - blockchain_timestamp_check_window;
  timestamps.reserve(h - offset);
  for(;offset < h; ++offset)
  {
    timestamps.push_back(m_db->get_block_timestamp(offset));
  }

  return check_block_timestamp(timestamps, b, median_ts);
}
//------------------------------------------------------------------
void Blockchain::return_tx_to_pool(std::vector<std::pair<transaction, string_blob>> &txs)
{
  for (auto& tx : txs)
  {
    cryptonote::tx_verification_context tvc = AUTO_VAL_INIT(tvc);
    // We assume that if they were in a block, the transactions are already
    // known to the network as a whole. However, if we had mined that block,
    // that might not be always true. Unlikely though, and always relaying
    // these again might cause a spike of traffic as many nodes re-relay
    // all the transactions in a popped block when a reorg happens.
    const size_t weight = tx.second.size();
    const crypto::hash tx_hash = get_transaction_hash(tx.first);
    if (!m_tx_pool.add_tx(tx.first, tx_hash, tx.second, weight, tvc, relay_method::block, true))
    {
      LOG_ERROR("Failed to return taken transaction with hash: " << get_transaction_hash(tx.first) << " to tx_pool");
    }
  }
}
//------------------------------------------------------------------
bool Blockchain::flush_txes_from_pool(const std::span<const crypto::hash>txids)
{
  LOCK_LOCKABLE_OBJECT(m_tx_pool);

  bool res = true;
  for (const auto &txid: txids)
  {
    cryptonote::transaction tx;
    cryptonote::string_blob txblob;
    size_t tx_weight;
    uint64_t fee;
    bool relayed, do_not_relay, double_spend_seen, pruned;
    LOG_INFO("Removing txid " << txid << " from the pool");
    if(m_tx_pool.have_tx(txid, relay_category::all) && !m_tx_pool.take_tx(txid, tx, txblob, tx_weight, fee, relayed, do_not_relay, double_spend_seen, pruned))
    {
      LOG_ERROR("Failed to remove txid " << txid << " from the pool");
      res = false;
    }
  }
  return res;
}
//------------------------------------------------------------------
//      Needs to validate the block and acquire each transaction from the
//      transaction mem_pool, then pass the block and transactions to
//      m_db->add_block()
bool Blockchain::handle_block_to_main_chain(const block& bl, const crypto::hash& id, block_verification_context& bvc, bool notify/* = true*/)
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  TIME_MEASURE_START(block_processing_time);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  TIME_MEASURE_START(t1);

  db_rtxn_guard rtxn_guard(m_db);
  uint64_t blockchain_height;
  const crypto::hash top_hash = get_tail_id(blockchain_height);
  ++blockchain_height; // block height to chain height
  if(bl.prev_id != top_hash)
  {
    LOG_ERROR_VER("Block with id: " << id << std::endl << "has wrong prev_id: " << bl.prev_id << std::endl << "expected: " << top_hash);
    bvc.m_verifivation_failed = true;
leave:
    return false;
  }

  TIME_MEASURE_FINISH(t1);
  TIME_MEASURE_START(t2);

  // make sure block timestamp is not less than the median timestamp
  // of a set number of the most recent blocks.
  if(!check_block_timestamp(bl))
  {
    LOG_ERROR_VER("Block with id: " << id << std::endl << "has invalid timestamp: " << bl.timestamp);
    bvc.m_verifivation_failed = true;
    goto leave;
  }

  TIME_MEASURE_FINISH(t2);
  //check proof of work
  TIME_MEASURE_START(target_calculating_time);

  // get the target difficulty for the block.
  // the calculation can overflow, among other failure cases,
  // so we need to check the return type.
  // FIXME: get_difficulty_for_next_block can also assert, look into
  // changing this to throwing exceptions instead so we can clean up.
  diff_t current_diffic = get_difficulty_for_next_block();
  LOG_ERROR_AND_RETURN_UNLESS(current_diffic, false, "!!!!!!!!! difficulty overhead !!!!!!!!!");

  TIME_MEASURE_FINISH(target_calculating_time);

  TIME_MEASURE_START(longhash_calculating_time);

  crypto::hash proof_of_work = {{0xff}};

  // Formerly the code below contained an if loop with the following condition
  // !m_checkpoints.is_in_checkpoint_zone(get_current_blockchain_height())
  // however, this caused the daemon to not bother checking PoW for blocks
  // before checkpoints, which is very dangerous behaviour. We moved the PoW
  // validation out of the next chunk of code to make sure that we correctly
  // check PoW now.
  // FIXME: height parameter is not used...should it be used or should it not
  // be a parameter?
  // validate proof_of_work versus difficulty target
  bool precomputed = false;
  bool fast_check = false;
  if (!fast_check)
  {
    auto it = m_blocks_longhash_table.find(id);
    if (it != m_blocks_longhash_table.end())
    {
      precomputed = true;
      proof_of_work = it->second;
    }
    else
      proof_of_work = get_mining_hash(bl);

    // validate proof_of_work versus difficulty target
    if(!check_hash(proof_of_work, current_diffic))
    {
      LOG_ERROR_VER("Block with id: " << id << std::endl << "does not have enough proof of work: " << proof_of_work << " at height " << blockchain_height << ", unexpected difficulty: " << current_diffic);
      bvc.m_verifivation_failed = true;
      bvc.m_bad_pow = true;
      goto leave;
    }
  }

  TIME_MEASURE_FINISH(longhash_calculating_time);
  if (precomputed)
    longhash_calculating_time += m_fake_pow_calc_time;

  TIME_MEASURE_START(t3);

  // sanity check basic miner tx properties;
  if(!prevalidate_miner_transaction(bl, blockchain_height))
  {
    LOG_ERROR_VER("Block with id: " << id << " failed to pass prevalidation");
    bvc.m_verifivation_failed = true;
    goto leave;
  }

  size_t coinbase_weight = get_transaction_weight(bl.miner_tx);
  size_t cumulative_block_weight = coinbase_weight;

  std::vector<std::pair<transaction, string_blob>> txs;
  output_spend_public_key_images_container keys;

  uint64_t fee_summary = 0;
  uint64_t t_checktx = 0;
  uint64_t t_exists = 0;
  uint64_t t_pool = 0;
  uint64_t t_dblspnd = 0;
  uint64_t n_pruned = 0;
  TIME_MEASURE_FINISH(t3);

// XXX old code adds miner tx here

  size_t tx_index = 0;
  // Iterate over the block's transaction hashes, grabbing each
  // from the tx_pool and validating them.  Each is then added
  // to txs.  Keys spent in each are added to <keys> by the double spend check.
  txs.reserve(bl.tx_hashes.size());
  for (const crypto::hash& tx_id : bl.tx_hashes)
  {
    transaction tx_tmp;
    string_blob txblob;
    size_t tx_weight = 0;
    uint64_t fee = 0;
    bool relayed = false, do_not_relay = false, double_spend_seen = false, pruned = false;
    TIME_MEASURE_START(aa);

// XXX old code does not check whether tx exists
    if (m_db->tx_exists(tx_id))
    {
      LOG_ERROR("Block with id: " << id << " attempting to add transaction already in blockchain with id: " << tx_id);
      bvc.m_verifivation_failed = true;
      return_tx_to_pool(txs);
      goto leave;
    }

    TIME_MEASURE_FINISH(aa);
    t_exists += aa;
    TIME_MEASURE_START(bb);

    // get transaction with hash <tx_id> from tx_pool
    if(!m_tx_pool.take_tx(tx_id, tx_tmp, txblob, tx_weight, fee, relayed, do_not_relay, double_spend_seen, pruned))
    {
      LOG_ERROR_VER("Block with id: " << id  << " has at least one unknown transaction with id: " << tx_id);
      bvc.m_verifivation_failed = true;
      return_tx_to_pool(txs);
      goto leave;
    }
    if (pruned)
      ++n_pruned;

    TIME_MEASURE_FINISH(bb);
    t_pool += bb;
    // add the transaction to the temp list of transactions, so we can either
    // store the list of transactions all at once or return the ones we've
    // taken from the tx_pool back to it if the block fails verification.
    txs.push_back(std::make_pair(std::move(tx_tmp), std::move(txblob)));
    transaction &tx = txs.back().first;
    TIME_MEASURE_START(dd);

    // FIXME: the storage should not be responsible for validation.
    //        If it does any, it is merely a sanity check.
    //        Validation is the purview of the Blockchain class
    //        - TW
    //
    // ND: this is not needed, db->add_block() checks for duplicate output_spend_public_key_images and fails accordingly.
    // if (!check_for_double_spend(tx, keys))
    // {
    //     LOG_PRINT_L0("Double spend detected in transaction (id: " << tx_id);
    //     bvc.m_verifivation_failed = true;
    //     break;
    // }

    TIME_MEASURE_FINISH(dd);
    t_dblspnd += dd;
    TIME_MEASURE_START(cc);

    {
      // validate that transaction inputs and the keys spending them are correct.
      tx_verification_context tvc;
      if(!check_tx_inputs(tx, tvc))
      {
        LOG_ERROR_VER("Block with id: " << id  << " has at least one transaction (id: " << tx_id << ") with wrong inputs.");

        //TODO: why is this done?  make sure that keeping invalid blocks makes sense.
        add_block_as_invalid(bl, id);
        LOG_ERROR_VER("Block with id " << id << " added as invalid because of wrong inputs in transactions");
        LOG_ERROR_VER("tx_index " << tx_index << ", m_blocks_txs_check " << m_blocks_txs_check.size() << ":");
        for (const auto &h: m_blocks_txs_check) LOG_ERROR_VER("  " << h);
        bvc.m_verifivation_failed = true;
        return_tx_to_pool(txs);
        goto leave;
      }
    }
    TIME_MEASURE_FINISH(cc);
    t_checktx += cc;
    fee_summary += fee;
    cumulative_block_weight += tx_weight;
  }

  // if we were syncing pruned blocks
  if (n_pruned > 0)
  {
    if (blockchain_height >= m_blocks_hash_check.size() || m_blocks_hash_check[blockchain_height].second == 0)
    {
      LOG_ERROR("Block at " << blockchain_height << " is pruned, but we do not have a weight for it");
      goto leave;
    }
    cumulative_block_weight = m_blocks_hash_check[blockchain_height].second;
  }

  m_blocks_txs_check.clear();

  TIME_MEASURE_START(vmt);
  uint64_t base_reward = 0;
  uint64_t already_generated_coins = blockchain_height ? m_db->get_block_already_generated_coins(blockchain_height - 1) : 0;
  if(!validate_miner_transaction(bl, cumulative_block_weight, fee_summary, base_reward, bvc.m_partial_block_reward))
  {
    LOG_ERROR_VER("Block with id: " << id << " has incorrect miner transaction");
    bvc.m_verifivation_failed = true;
    return_tx_to_pool(txs);
    goto leave;
  }

  TIME_MEASURE_FINISH(vmt);
  size_t block_weight;
  diff_t cumulative_difficulty;

  // populate various metadata about the block to be stored alongside it.
  block_weight = cumulative_block_weight;
  cumulative_difficulty = current_diffic;
  // In the "tail" state when the minimum subsidy (implemented in get_block_reward) is in effect, the number of
  // coins will eventually exceed MONEY_SUPPLY and overflow a uint64. To prevent overflow, cap already_generated_coins
  // at MONEY_SUPPLY. already_generated_coins is only used to compute the block subsidy and MONEY_SUPPLY yields a
  // subsidy of 0 under the base formula and therefore the minimum subsidy >0 in the tail state.
  already_generated_coins = base_reward < (MONEY_SUPPLY-already_generated_coins) ? already_generated_coins + base_reward : MONEY_SUPPLY;
  if(blockchain_height)
    cumulative_difficulty += m_db->get_block_cumulative_difficulty(blockchain_height - 1);

  TIME_MEASURE_FINISH(block_processing_time);
  if(precomputed)
    block_processing_time += m_fake_pow_calc_time;

  rtxn_guard.stop();
  TIME_MEASURE_START(addblock);
  uint64_t new_height = 0;
  if (!bvc.m_verifivation_failed)
  {
    try
    {
      uint64_t long_term_block_weight = get_max_block_weight(cryptonote::get_block_height(bl));
      cryptonote::string_blob bd = cryptonote::block_to_blob(bl);
      new_height = m_db->add_block(std::make_pair(std::move(bl), std::move(bd)), block_weight, long_term_block_weight, cumulative_difficulty, already_generated_coins, txs);
    }
    catch (const KEY_IMAGE_EXISTS& e)
    {
      LOG_ERROR("Error adding block with hash: " << id << " to blockchain, what = " << e.what());
      m_batch_success = false;
      bvc.m_verifivation_failed = true;
      return_tx_to_pool(txs);
      return false;
    }
    catch (const std::exception& e)
    {
      //TODO: figure out the best way to deal with this failure
      LOG_ERROR("Error adding block with hash: " << id << " to blockchain, what = " << e.what());
      m_batch_success = false;
      bvc.m_verifivation_failed = true;
      return_tx_to_pool(txs);
      return false;
    }
  }
  else
    {
      LOG_ERROR("Blocks that failed verification should not reach here");
    }

  TIME_MEASURE_FINISH(addblock);

  // do this after updating the hard fork state since the weight limit may change due to fork
  if (!update_next_cumulative_weight_limit())
    {
      LOG_ERROR("Failed to update next cumulative weight limit");
      pop_block_from_blockchain();
      return false;
    }

  LOG_INFO
    (
     std::endl
     << config::lol::plus_sep << "BLOCK SUCCESSFULLY ADDED" << std::endl
     << std::endl
     << "id:             " << id << std::endl
     << "PoW:            " << proof_of_work << std::endl
     << "height:         " << new_height - 1 << std::endl
     << "difficulty:     " << current_diffic << std::endl
     << "block reward:   " << print_money(fee_summary + base_reward)
     << config::lol::money_symbol << " ( " << print_money(base_reward)
     << config::lol::money_symbol << " + " << print_money(fee_summary)
     << config::lol::money_symbol << " )" << std::endl
     << "size:           " << cumulative_block_weight << " bytes" << std::endl
    );
  if(m_show_time_stats)
  {
    LOG_INFO("Height: " << new_height << " coinbase weight: " << coinbase_weight << " cumm: "
        << cumulative_block_weight << " p/t: " << block_processing_time << " ("
        << target_calculating_time << "/" << longhash_calculating_time << "/"
        << t1 << "/" << t2 << "/" << t3 << "/" << t_exists << "/" << t_pool
        << "/" << t_checktx << "/" << t_dblspnd << "/" << vmt << "/" << addblock << ")ms");
  }

  bvc.m_added_to_main_chain = true;
  ++m_sync_counter;

  // appears to be a NOP *and* is called elsewhere.  wat?
  m_tx_pool.on_blockchain_inc(new_height, id);
  get_difficulty_for_next_block(); // just to cache it
  invalidate_block_template_cache();


  for (const auto& notifier: m_block_notifiers)
    notifier(new_height - 1, std::vector{bl});

  return true;
}
//------------------------------------------------------------------
bool Blockchain::update_next_cumulative_weight_limit()
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  if (!m_db->is_read_only())
    m_db->add_max_block_size(get_max_block_weight(get_current_blockchain_height()));

  return true;
}
//------------------------------------------------------------------
bool Blockchain::add_new_block(const block& bl, block_verification_context& bvc)
{
  try
  {

  LOG_PRINT_L3("Blockchain::" << __func__);
  crypto::hash id = get_block_hash(bl);
  LOCK_LOCKABLE_OBJECT(m_tx_pool);//to avoid deadlock lets lock tx_pool for whole add/reorganize process
  std::lock_guard<std::recursive_mutex> lock1(m_blockchain_lock);
  db_rtxn_guard rtxn_guard(m_db);
  if(have_block(id))
  {
    LOG_PRINT_L3("block with id = " << id << " already exists");
    bvc.m_already_exists = true;
    m_blocks_txs_check.clear();
    return false;
  }

  //check that block refers to chain tail
  if(!(bl.prev_id == get_tail_id()))
  {
    //chain switching or wrong block
    bvc.m_added_to_main_chain = false;
    rtxn_guard.stop();
    bool r = handle_alternative_block(bl, id, bvc);
    m_blocks_txs_check.clear();
    return r;
    //never relay alternative blocks
  }

  rtxn_guard.stop();
  return handle_block_to_main_chain(bl, id, bvc);

  }
  catch (const std::exception &e)
  {
    LOG_ERROR("Exception at [add_new_block], what=" << e.what());
    bvc.m_verifivation_failed = true;
    return false;
  }
}

//------------------------------------------------------------------
void Blockchain::block_longhash_worker(uint64_t height, const std::span<const block> blocks, std::unordered_map<crypto::hash, crypto::hash> &map) const
{
  TIME_MEASURE_START(t);

  for (const auto & block : blocks)
  {
    if (m_cancel)
       break;
    crypto::hash id = get_block_hash(block);
    crypto::hash pow = get_mining_hash(block);
    map.emplace(id, pow);
  }

  TIME_MEASURE_FINISH(t);
}

//------------------------------------------------------------------
bool Blockchain::cleanup_handle_incoming_blocks(bool force_sync)
{
  bool success = false;

  LOG_TRACE("Blockchain::" << __func__);
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
  TIME_MEASURE_START(t1);

  try
  {
    if (m_batch_success)
    {
      m_db->batch_stop();
      if (m_reset_timestamps_and_difficulties_height)
      {
        m_timestamps_and_difficulties_height = 0;
        m_reset_timestamps_and_difficulties_height = false;
      }
    }
    else
      m_db->batch_abort();
    success = true;
  }
  catch (const std::exception &e)
  {
    LOG_ERROR("Exception in cleanup_handle_incoming_blocks: " << e.what());
  }

  if (success && m_sync_counter > 0)
  {
    if (force_sync)
    {
      if(m_db_sync_mode != db_nosync)
        store_blockchain();
      m_sync_counter = 0;
    }
    else if (m_db_sync_threshold && ((m_db_sync_on_blocks && m_sync_counter >= m_db_sync_threshold) || (!m_db_sync_on_blocks && m_bytes_to_sync >= m_db_sync_threshold)))
    {
      LOG_DEBUG("Sync threshold met, syncing");
      if(m_db_sync_mode == db_async)
      {
        m_sync_counter = 0;
        m_bytes_to_sync = 0;
        m_async_service.dispatch(std::bind(&Blockchain::store_blockchain, this));
      }
      else if(m_db_sync_mode == db_sync)
      {
        store_blockchain();
      }
      else // db_nosync
      {
        // DO NOTHING, not required to call sync.
      }
    }
  }

  TIME_MEASURE_FINISH(t1);
  m_blocks_longhash_table.clear();
  m_scan_table.clear();
  m_blocks_txs_check.clear();

  // when we're well clear of the precomputed hashes, free the memory
  if (!m_blocks_hash_check.empty() && m_db->height() > m_blocks_hash_check.size() + 4096)
  {
    LOG_INFO("Dumping block hashes, we're now 4k past " << m_blocks_hash_check.size());
    m_blocks_hash_check.clear();
    m_blocks_hash_check.shrink_to_fit();
  }

  m_tx_pool.unlock();

  return success;
}

//------------------------------------------------------------------
void Blockchain::output_scan_worker(const uint64_t amount, const std::vector<uint64_t> &offsets, std::vector<output_data_t> &outputs) const
{
  try
  {
    m_db->get_output_key(std::span<const uint64_t>(&amount, 1), offsets, outputs, true);
  }
  catch (const std::exception& e)
  {
    LOG_ERROR_VER("EXCEPTION: " << e.what());
  }
  catch (...)
  {

  }
}

bool Blockchain::has_block_weights(uint64_t height, uint64_t nblocks) const
{
  LOG_ERROR_AND_RETURN_UNLESS(nblocks > 0, false, "nblocks is 0");
  uint64_t last_block_height = height + nblocks - 1;
  if (last_block_height >= m_blocks_hash_check.size())
    return false;
  for (uint64_t h = height; h <= last_block_height; ++h)
    if (m_blocks_hash_check[h].second == 0)
      return false;
  return true;
}

//------------------------------------------------------------------
// ND: Speedups:
// 1. Thread long_hash computations if possible
// 2. Group all amounts (from txs) and related absolute offsets and form a table of tx_prefix_hash
//    vs [output_spend_public_key_image, output_keys] (m_scan_table). This is faster because it takes advantage of bulk queries
//    and is threaded if possible. The table (m_scan_table) will be used later when querying output
//    keys.
bool Blockchain::prepare_handle_incoming_blocks(const std::span<const block_complete_entry> blocks_entry, std::vector<block> &blocks)
{
  LOG_TRACE("Blockchain::" << __func__);
  TIME_MEASURE_START(prepare);
  bool stop_batch;
  uint64_t bytes = 0;
  size_t total_txs = 0;
  blocks.clear();

  // Order of locking must be:
  //  m_incoming_tx_lock (optional)
  //  m_tx_pool lock
  //  blockchain lock
  //
  //  Something which takes the blockchain lock may never take the txpool lock
  //  if it has not provably taken the txpool lock earlier
  //
  //  The txpool lock is now taken in prepare_handle_incoming_blocks
  //  and released in cleanup_handle_incoming_blocks. This avoids issues
  //  when something uses the pool, which now uses the blockchain and
  //  needs a batch, since a batch could otherwise be active while the
  //  txpool and blockchain locks were not held

  m_tx_pool.lock();
  std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);

  if(blocks_entry.size() == 0)
    return false;

  for (const auto &entry : blocks_entry)
  {
    bytes += entry.block.size();
    for (const auto &tx_blob : entry.txs)
    {
      bytes += tx_blob.blob.size();
    }
    total_txs += entry.txs.size();
  }
  m_bytes_to_sync += bytes;
  while (!(stop_batch = m_db->batch_start(blocks_entry.size(), bytes))) {
    m_blockchain_lock.unlock();
    m_tx_pool.unlock();
    epee::misc_utils::sleep_no_w(1000);
    m_tx_pool.lock();
    m_blockchain_lock.lock();
  }
  m_batch_success = true;

  const uint64_t height = m_db->height();
  if ((height + blocks_entry.size()) < m_blocks_hash_check.size())
    return true;

  bool blocks_exist = false;
  tools::threadpool& tpool = tools::threadpool::getInstance();
  unsigned threads = tpool.get_max_concurrency();
  blocks.resize(blocks_entry.size());

  {
    std::unordered_map<crypto::hash, crypto::hash> map;

    const crypto::hash tophash = m_db->top_block_hash();
    for (size_t blockidx = 0; const auto& entry: blocks_entry)
    {
      block &block = blocks[blockidx];
      crypto::hash block_hash;

      if (!parse_and_validate_block_from_blob(entry.block, block, block_hash))
        return false;

      // check first block and skip all blocks if its not chained properly
      if (blockidx == 0)
      {
        if (block.prev_id != tophash)
        {
          LOG_DEBUG("Skipping prepare blocks. New blocks don't belong to chain.");
          blocks.clear();
          return true;
        }
      }
      if (have_block(block_hash))
        blocks_exist = true;

      blockidx++;
    }

    if (!blocks_exist)
    {
      m_blocks_longhash_table.clear();
      tools::threadpool::waiter waiter(tpool);
      m_prepare_height = height;
      m_prepare_nblocks = blocks_entry.size();
      m_prepare_blocks = &blocks;
      Blockchain::block_longhash_worker
        (
         height
         , blocks
         , map
         );

      m_prepare_height = 0;

      if (m_cancel)
         return false;

      m_blocks_longhash_table.insert(map.begin(), map.end());
    }
  }

  if (m_cancel)
    return false;

  if (blocks_exist)
  {
    LOG_DEBUG("Skipping remainder of prepare blocks. Blocks exist.");
    return true;
  }

  m_fake_scan_time = 0;
  m_fake_pow_calc_time = 0;

  m_scan_table.clear();

  TIME_MEASURE_FINISH(prepare);
  m_fake_pow_calc_time = prepare / blocks_entry.size();

  if (blocks_entry.size() > 1 && threads > 1 && m_show_time_stats)
    LOG_DEBUG("Prepare blocks took: " << prepare << " ms");

  TIME_MEASURE_START(scantable);

  // [input] stores all unique amounts found
  std::vector < uint64_t > amounts;
  // [input] stores all absolute_offsets for each amount
  std::map<uint64_t, std::vector<uint64_t>> offset_map;
  // [output] stores all output_data_t for each absolute_offset
  std::map<uint64_t, std::vector<output_data_t>> tx_map;
  std::vector<std::pair<cryptonote::transaction, crypto::hash>> txes(total_txs);

#define SCAN_TABLE_QUIT(m) \
        do { \
            LOG_ERROR_VER(m) ;\
            m_scan_table.clear(); \
            return false; \
        } while(0); \

  // generate sorted tables for all amounts and absolute offsets
  size_t tx_index = 0, block_index = 0;
  for (const auto &entry : blocks_entry)
  {
    if (m_cancel)
      return false;

    for (const auto &tx_blob : entry.txs)
    {
      if (tx_index >= txes.size())
        SCAN_TABLE_QUIT("tx_index is out of sync");
      transaction &tx = txes[tx_index].first;
      crypto::hash &tx_prefix_hash = txes[tx_index].second;
      ++tx_index;

      const auto maybeTx = cryptonote::maybe_tx_from_blob(tx_blob.blob);
      if (!maybeTx) {
        SCAN_TABLE_QUIT("Could not parse tx from incoming blocks.");
      }

      tx = *maybeTx;

      tx_prefix_hash = cryptonote::get_transaction_prefix_hash(tx);

      auto its = m_scan_table.find(tx_prefix_hash);
      if (its != m_scan_table.end())
        SCAN_TABLE_QUIT("Duplicate tx found from incoming blocks.");

      m_scan_table.emplace(tx_prefix_hash, std::unordered_map<crypto::output_spend_public_key_image, std::vector<output_data_t>>());
      its = m_scan_table.find(tx_prefix_hash);
      assert(its != m_scan_table.end());

      // get all amounts from tx.vin(s)
      for (const auto &txin : tx.vin)
      {
        const txin_to_key &in_to_key = boost::get < txin_to_key > (txin);

        // check for duplicate
        auto it = its->second.find(in_to_key.output_spend_public_key_image);
        if (it != its->second.end())
          SCAN_TABLE_QUIT("Duplicate output_spend_public_key_image found from incoming blocks.");

        amounts.push_back(in_to_key.amount);
      }

      // sort and remove duplicate amounts from amounts list
      std::sort(amounts.begin(), amounts.end());
      auto last = std::unique(amounts.begin(), amounts.end());
      amounts.erase(last, amounts.end());

      // add amount to the offset_map and tx_map
      for (const uint64_t &amount : amounts)
      {
        if (offset_map.find(amount) == offset_map.end())
          offset_map.emplace(amount, std::vector<uint64_t>());

        if (tx_map.find(amount) == tx_map.end())
          tx_map.emplace(amount, std::vector<output_data_t>());
      }

      // add new absolute_offsets to offset_map
      for (const auto &txin : tx.vin)
      {
        const txin_to_key &in_to_key = boost::get < txin_to_key > (txin);
        // no need to check for duplicate here.
        auto absolute_offsets = relative_output_offsets_to_absolute(in_to_key.output_relative_offsets);
        for (const auto & offset : absolute_offsets)
          offset_map[in_to_key.amount].push_back(offset);

      }
    }
    ++block_index;
  }

  // sort and remove duplicate absolute_offsets in offset_map
  for (auto &offsets : offset_map)
  {
    std::sort(offsets.second.begin(), offsets.second.end());
    auto last = std::unique(offsets.second.begin(), offsets.second.end());
    offsets.second.erase(last, offsets.second.end());
  }

  // gather all the output keys
  threads = tpool.get_max_concurrency();
  if (!m_db->can_thread_bulk_indices())
    threads = 1;

  if (threads > 1 && amounts.size() > 1)
  {
    tools::threadpool::waiter waiter(tpool);

    for (size_t i = 0; i < amounts.size(); i++)
    {
      uint64_t amount = amounts[i];
      tpool.submit(&waiter, std::bind(&Blockchain::output_scan_worker, this, amount, std::cref(offset_map[amount]), std::ref(tx_map[amount])), true);
    }
    if (!waiter.wait())
      return false;
  }
  else
  {
    for (size_t i = 0; i < amounts.size(); i++)
    {
      uint64_t amount = amounts[i];
      output_scan_worker(amount, offset_map[amount], tx_map[amount]);
    }
  }

  // now generate a table for each tx_prefix and output_spend_public_key_image hashes
  tx_index = 0;
  for (const auto &entry : blocks_entry)
  {
    if (m_cancel)
      return false;

    for (const auto &tx_blob : entry.txs)
    {
      (void)tx_blob;
      if (tx_index >= txes.size())
        SCAN_TABLE_QUIT("tx_index is out of sync");
      const transaction &tx = txes[tx_index].first;
      const crypto::hash &tx_prefix_hash = txes[tx_index].second;
      ++tx_index;

      auto its = m_scan_table.find(tx_prefix_hash);
      if (its == m_scan_table.end())
        SCAN_TABLE_QUIT("Tx not found on scan table from incoming blocks.");

      for (const auto &txin : tx.vin)
      {
        const txin_to_key &in_to_key = boost::get < txin_to_key > (txin);
        auto needed_offsets = relative_output_offsets_to_absolute(in_to_key.output_relative_offsets);

        std::vector<output_data_t> outputs;
        for (const uint64_t & offset_needed : needed_offsets)
        {
          size_t pos = 0;
          bool found = false;

          for (const uint64_t &offset_found : offset_map[in_to_key.amount])
          {
            if (offset_needed == offset_found)
            {
              found = true;
              break;
            }

            ++pos;
          }

          if (found && pos < tx_map[in_to_key.amount].size())
            outputs.push_back(tx_map[in_to_key.amount].at(pos));
          else
            break;
        }

        its->second.emplace(in_to_key.output_spend_public_key_image, outputs);
      }
    }
  }

  TIME_MEASURE_FINISH(scantable);
  if (total_txs > 0)
  {
    m_fake_scan_time = scantable / total_txs;
    if(m_show_time_stats)
      LOG_DEBUG("Prepare scantable took: " << scantable << " ms");
  }

  return true;
}

void Blockchain::add_txpool_tx(const crypto::hash &txid, const cryptonote::string_blob &blob, const txpool_tx_meta_t &meta)
{
  m_db->add_txpool_tx(txid, blob, meta);
}

void Blockchain::update_txpool_tx(const crypto::hash &txid, const txpool_tx_meta_t &meta)
{
  m_db->update_txpool_tx(txid, meta);
}

void Blockchain::remove_txpool_tx(const crypto::hash &txid)
{
  m_db->remove_txpool_tx(txid);
}

uint64_t Blockchain::get_txpool_tx_count(bool include_sensitive) const
{
  return m_db->get_txpool_tx_count(include_sensitive ? relay_category::all : relay_category::broadcasted);
}

bool Blockchain::get_txpool_tx_meta(const crypto::hash& txid, txpool_tx_meta_t &meta) const
{
  return m_db->get_txpool_tx_meta(txid, meta);
}

bool Blockchain::get_txpool_tx_blob(const crypto::hash& txid, cryptonote::string_blob &bd, relay_category tx_category) const
{
  return m_db->get_txpool_tx_blob(txid, bd, tx_category);
}

cryptonote::string_blob Blockchain::get_txpool_tx_blob(const crypto::hash& txid, relay_category tx_category) const
{
  return m_db->get_txpool_tx_blob(txid, tx_category);
}

bool Blockchain::for_all_txpool_txes(std::function<bool(const crypto::hash&, const txpool_tx_meta_t&, const cryptonote::string_blob_view)> f, bool include_blob, relay_category tx_category) const
{
  return m_db->for_all_txpool_txes(f, include_blob, tx_category);
}

bool Blockchain::txpool_tx_matches_category(const crypto::hash& tx_hash, relay_category category)
{
  return m_db->txpool_tx_matches_category(tx_hash, category);
}

void Blockchain::set_user_options(bool sync_on_blocks, uint64_t sync_threshold, blockchain_db_sync_mode sync_mode)
{
  if (sync_mode == db_defaultsync)
  {
    m_db_default_sync = true;
    sync_mode = db_async;
  }
  m_db_sync_mode = sync_mode;
  m_db_sync_on_blocks = sync_on_blocks;
  m_db_sync_threshold = sync_threshold;
}

void Blockchain::add_block_notify(std::function<void(const uint64_t, const std::vector<block>)>&& notify)
{
  if (notify)
  {
    std::lock_guard<std::recursive_mutex> lock(m_blockchain_lock);
    m_block_notifiers.push_back(std::move(notify));
  }
}

void Blockchain::safesyncmode(const bool onoff)
{
  /* all of this is no-op'd if the user set a specific
   * --db-sync-mode at startup.
   */
  if (m_db_default_sync)
  {
    m_db->safesyncmode(onoff);
    m_db_sync_mode = onoff ? db_nosync : db_async;
  }
}

uint64_t Blockchain::get_difficulty_target() const
{
  return DIFFICULTY_TARGET_IN_SECONDS;
}

std::vector<std::pair<Blockchain::block_extended_info,std::vector<crypto::hash>>> Blockchain::get_alternative_chains() const
{
  std::vector<std::pair<Blockchain::block_extended_info,std::vector<crypto::hash>>> chains;

  blocks_ext_by_hash alt_blocks;
  alt_blocks.reserve(m_db->get_alt_block_count());
  m_db->for_all_alt_blocks([&alt_blocks](const crypto::hash &blkid, const cryptonote::alt_block_data_t &data, const cryptonote::string_blob_view blob) {
    cryptonote::block bl;
    block_extended_info bei;
    const auto maybeBlock = maybe_block_from_blob(blob);
    if (maybeBlock)
    {
      bei.bl = *maybeBlock;
      bei.height = data.height;
      bei.block_cumulative_weight = data.cumulative_weight;
      bei.cumulative_difficulty = data.cumulative_difficulty_high;
      bei.cumulative_difficulty = (bei.cumulative_difficulty << 64) + data.cumulative_difficulty_low;
      bei.already_generated_coins = data.already_generated_coins;
      alt_blocks.insert(std::make_pair(cryptonote::get_block_hash(bei.bl), std::move(bei)));
    }
    else
      LOG_ERROR("Failed to parse block from blob");
    return true;
  });

  for (const auto &i: alt_blocks)
  {
    const crypto::hash top = cryptonote::get_block_hash(i.second.bl);
    bool found = false;
    for (const auto &j: alt_blocks)
    {
      if (j.second.bl.prev_id == top)
      {
        found = true;
        break;
      }
    }
    if (!found)
    {
      std::vector<crypto::hash> chain;
      auto h = i.second.bl.prev_id;
      chain.push_back(top);
      blocks_ext_by_hash::const_iterator prev;
      while ((prev = alt_blocks.find(h)) != alt_blocks.end())
      {
        chain.push_back(h);
        h = prev->second.bl.prev_id;
      }
      chains.push_back(std::make_pair(i.second, chain));
    }
  }
  return chains;
}

void Blockchain::cancel()
{
  m_cancel = true;
}

void Blockchain::lock()
{
  m_blockchain_lock.lock();
}

void Blockchain::unlock()
{
  m_blockchain_lock.unlock();
}

bool Blockchain::for_all_output_spend_public_key_images(std::function<bool(const crypto::output_spend_public_key_image&)> f) const
{
  return m_db->for_all_output_spend_public_key_images(f);
}

bool Blockchain::for_blocks_range(const uint64_t& h1, const uint64_t& h2, std::function<bool(uint64_t, const crypto::hash&, const block&)> f) const
{
  return m_db->for_blocks_range(h1, h2, f);
}

bool Blockchain::for_all_transactions(std::function<bool(const crypto::hash&, const cryptonote::transaction&)> f) const
{
  return m_db->for_all_transactions(f);
}

bool Blockchain::for_all_outputs(std::function<bool(uint64_t amount, const crypto::hash &tx_hash, uint64_t height, size_t tx_idx)> f) const
{
  return m_db->for_all_outputs(f);
}

bool Blockchain::for_all_outputs(uint64_t amount, std::function<bool(uint64_t height)> f) const
{
  return m_db->for_all_outputs(amount, f);
}

void Blockchain::invalidate_block_template_cache()
{
  LOG_DEBUG("Invalidating block template cache");
  m_btc_valid = false;
}

void Blockchain::cache_block_template(const block &b, const cryptonote::spend_view_public_keys &address, const string_blob &nonce, const diff_t &diff, uint64_t height, uint64_t expected_reward, uint64_t pool_cookie)
{
  LOG_DEBUG("Setting block template cache");
  m_btc = b;
  m_btc_address = address;
  m_btc_nonce = nonce;
  m_btc_difficulty = diff;
  m_btc_height = height;
  m_btc_expected_reward = expected_reward;
  m_btc_pool_cookie = pool_cookie;
  m_btc_valid = true;
}

//------------------------------------------------------------------
// This function validates transaction inputs and their keys.
// FIXME: consider moving functionality specific to one input into
//        check_tx_input() rather than here, and use this function simply
//        to iterate the inputs as necessary (splitting the task
//        using threads, etc.)
bool Blockchain::check_tx_inputs(transaction& tx, tx_verification_context &tvc, uint64_t* pmax_used_block_height) const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  size_t sig_index = 0;
  if(pmax_used_block_height)
    *pmax_used_block_height = 0;

  crypto::hash tx_prefix_hash = get_transaction_prefix_hash(tx);

  if (tx.vout.size() < 2)
  {
    LOG_ERROR_VER("Tx " << get_transaction_hash(tx) << " has fewer than two outputs");
    tvc.m_too_few_outputs = true;
    return false;
  }

  // from hard fork 2, we require mixin at least 2 unless one output cannot mix with 2 others
  // if one output cannot mix with 2 others, we accept at most 1 output that can mix
  {
    size_t n_unmixable = 0, n_mixable = 0;
    size_t min_actual_mixin = std::numeric_limits<size_t>::max();
    size_t max_actual_mixin = 0;
    const size_t min_mixin = config::lol::mixin;
    for (const auto& txin : tx.vin)
    {
      // non txin_to_key inputs will be rejected below
      if (txin.type() == typeid(txin_to_key))
      {
        const txin_to_key& in_to_key = boost::get<txin_to_key>(txin);
        if (in_to_key.amount == 0)
        {
          // always consider rct inputs mixable. Even if there's not enough rct
          // inputs on the chain to mix with, this is going to be the case for
          // just a few blocks right after the fork at most
          ++n_mixable;
        }
        else
        {
          uint64_t n_outputs = m_db->get_num_outputs(in_to_key.amount);
          LOG_DEBUG("output size " << print_money(in_to_key.amount) << ": " << n_outputs << " available");
          // n_outputs includes the output we're considering
          if (n_outputs <= min_mixin)
            ++n_unmixable;
          else
            ++n_mixable;
        }
        size_t ring_mixin = in_to_key.output_relative_offsets.size() - 1;
        if (ring_mixin < min_actual_mixin)
          min_actual_mixin = ring_mixin;
        if (ring_mixin > max_actual_mixin)
          max_actual_mixin = ring_mixin;
      }
    }
    LOG_DEBUG("Mixin: " << min_actual_mixin << "-" << max_actual_mixin);

    {
      if (min_actual_mixin != max_actual_mixin)
      {
        LOG_ERROR_VER("Tx " << get_transaction_hash(tx) << " has varying ring size (" << (min_actual_mixin + 1) << "-" << (max_actual_mixin + 1) << "), it should be constant");
        tvc.m_low_mixin = true;
        return false;
      }
    }

    if (min_actual_mixin != config::lol::mixin)
    {
      LOG_ERROR_VER("Tx " << get_transaction_hash(tx) << " has invalid ring size (" << (min_actual_mixin + 1) << "), it should be 32");
      tvc.m_low_mixin = true;
      return false;
    }

    // min/max tx version based on HF, and we accept v1 txes if having a non mixable
    const size_t max_tx_version = config::lol::tx_version;
    if (tx.version > max_tx_version)
    {
      LOG_ERROR_VER("transaction version " << (unsigned)tx.version << " is higher than max accepted version " << max_tx_version);
      tvc.m_verifivation_failed = true;
      return false;
    }
    const size_t min_tx_version = config::lol::tx_version;
    if (tx.version < min_tx_version)
    {
      LOG_ERROR_VER("transaction version " << (unsigned)tx.version << " is lower than min accepted version " << min_tx_version);
      tvc.m_verifivation_failed = true;
      return false;
    }
  }

  // from v7, sorted ins
  const bool sorted_output_spend_public_key_images =
    std::is_sorted
    (
     tx.vin.begin()
     , tx.vin.end()
     , [](const auto& x, const auto& y) {
       const txin_to_key x1 = boost::get<txin_to_key>(x);
       const txin_to_key y1 = boost::get<txin_to_key>(x);
       return x1.output_spend_public_key_image < y1.output_spend_public_key_image;
     }
     );

  if (!sorted_output_spend_public_key_images) {
    LOG_ERROR_VER("transaction has unsorted inputs");
    tvc.m_verifivation_failed = true;
    return false;
  }

  std::vector<std::vector<rct::output_public_data>> pubkeys(tx.vin.size());
  std::vector < uint64_t > results;
  results.resize(tx.vin.size(), 0);

  tools::threadpool& tpool = tools::threadpool::getInstance();
  tools::threadpool::waiter waiter(tpool);

  uint64_t max_used_block_height = 0;
  if (!pmax_used_block_height)
    pmax_used_block_height = &max_used_block_height;
  for (const auto& txin : tx.vin)
  {
    // make sure output being spent is of type txin_to_key, rather than
    // e.g. txin_gen, which is only used for miner transactions
    LOG_ERROR_AND_RETURN_UNLESS(txin.type() == typeid(txin_to_key), false, "wrong type id in tx input at Blockchain::check_tx_inputs");
    const txin_to_key& in_to_key = boost::get<txin_to_key>(txin);

    // make sure tx output has key offset(s) (is signed to be used)
    LOG_ERROR_AND_RETURN_UNLESS(in_to_key.output_relative_offsets.size(), false, "empty in_to_key.output_relative_offsets in transaction with id " << get_transaction_hash(tx));

    if(have_tx_keyimg_as_spent(in_to_key.output_spend_public_key_image))
    {
      LOG_ERROR_VER("Key image already spent in blockchain: " << epee::string_tools::pod_to_hex(in_to_key.output_spend_public_key_image));
      tvc.m_double_spend = true;
      return false;
    }

    // make sure that output being spent matches up correctly with the
    // signature spending it.
    if (!check_tx_input(tx.version, in_to_key, tx_prefix_hash, tx.ringct, pubkeys[sig_index], pmax_used_block_height))
    {
      LOG_ERROR_VER("Failed to check ring signature for tx " << get_transaction_hash(tx) << "  vin key with output_spend_public_key_image: " << in_to_key.output_spend_public_key_image << "  sig_index: " << sig_index);
      if (pmax_used_block_height) // a default value of NULL is used when called from Blockchain::handle_block_to_main_chain()
      {
        LOG_ERROR_VER("  *pmax_used_block_height: " << *pmax_used_block_height);
      }

      return false;
    }

    sig_index++;
  }
  // enforce min output age
  {
    LOG_ERROR_AND_RETURN_UNLESS(*pmax_used_block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE <= m_db->height(),
        false, "Transaction spends at least one output which is too young");
  }

  {
    if (!expand_transaction_2(tx, tx_prefix_hash, pubkeys))
    {
      LOG_ERROR_VER("Failed to expand rct signatures!");
      return false;
    }

    // from version 2, check ringct signatures
    // obviously, the original and simple rct APIs use decoys that's indexes
    // in opposite orders, because it'd be too simple otherwise...
    const rct::rctData &rv = tx.ringct;
    switch (rv.type)
    {
    case rct::RCTTypeNull: {
      // we only accept no signatures for coinbase txes
      LOG_ERROR_VER("Null rct signature on non-coinbase tx");
      return false;
    }
    case rct::RCTTypeCLSAG:
    {
      // check all this, either reconstructed (so should really pass), or not
      {
        if (pubkeys.size() != rv.decoys.size())
        {
          LOG_ERROR_VER("Failed to check ringct signatures: mismatched pubkeys/decoys size");
          return false;
        }
        for (size_t i = 0; i < pubkeys.size(); ++i)
        {
          if (pubkeys[i].size() != rv.decoys[i].size())
          {
            LOG_ERROR_VER("Failed to check ringct signatures: mismatched pubkeys/decoys size");
            return false;
          }
        }

        for (size_t n = 0; n < pubkeys.size(); ++n)
        {
          for (size_t m = 0; m < pubkeys[n].size(); ++m)
          {
            if (pubkeys[n][m].output_spend_pk != rv.decoys[n][m].output_spend_pk)
            {
              LOG_ERROR_VER("Failed to check ringct signatures: mismatched pubkey at vin " << n << ", index " << m);
              return false;
            }
            if (pubkeys[n][m].commit != rv.decoys[n][m].commit)
            {
              LOG_ERROR_VER("Failed to check ringct signatures: mismatched commitment at vin " << n << ", index " << m);
              return false;
            }
          }
        }
      }

      const size_t n_sigs = rv.p.CLSAGs.size();
      if (n_sigs != tx.vin.size())
      {
        LOG_ERROR_VER("Failed to check ringct signatures: mismatched MGs/vin sizes");
        return false;
      }
      for (size_t n = 0; n < tx.vin.size(); ++n)
      {
        bool error;
        error = memcmp(&boost::get<txin_to_key>(tx.vin[n]).output_spend_public_key_image, &rv.p.CLSAGs[n].signer_pk_image, 32);
        if (error)
        {
          LOG_ERROR_VER("Failed to check ringct signatures: mismatched key image");
          return false;
        }
      }

      if (!rct::verify_clsag_signatures(rv))
      {
        LOG_ERROR_VER("Failed to check ringct signatures!");
        return false;
      }
      break;
    }
    default:
      LOG_ERROR_VER("Unsupported rct type: " << rv.type);
      return false;
    }
  }
  return true;
}

namespace cryptonote {
template bool Blockchain::get_transactions(const std::span<const crypto::hash>, std::vector<transaction>&, std::vector<crypto::hash>&) const;
template bool Blockchain::get_split_transactions_blobs(const std::span<const crypto::hash>, std::vector<std::pair<crypto::hash, cryptonote::string_blob>>&, std::vector<crypto::hash>&) const;
}
