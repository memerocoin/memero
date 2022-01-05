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

#include "core_rpc_server.h"
#include "core_rpc_server_error_codes.h"

#include "network/rpc/rpc_args.h"
#include "network/type/parse.h"

#include "cryptonote/tx/functional/tx_check.h"
#include "cryptonote/basic/functional/tx_extra.hpp"
#include "cryptonote/basic/functional/format_utils.hpp"

#include "config/version/version.hpp"





using namespace constant;

namespace
{
  void add_reason(std::string &reasons, const char *reason)
  {
    if (!reasons.empty())
      reasons += ", ";
    reasons += reason;
  }

  void store_128(boost::multiprecision::uint128_t value, uint64_t &slow64, std::string &swide, uint64_t &stop64)
  {
    slow64 = (value & 0xffffffffffffffff).convert_to<uint64_t>();
    swide = cryptonote::diff_to_hex(value);
    stop64 = ((value >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
  }

  void store_difficulty(cryptonote::diff_t difficulty, uint64_t &sdiff, std::string &swdiff, uint64_t &stop64)
  {
    store_128(difficulty, sdiff, swdiff, stop64);
  }
}

namespace cryptonote
{

  //-----------------------------------------------------------------------------------
  void core_rpc_server::init_options(boost::program_options::options_description& desc)
  {
    command_line::add_arg(desc, arg_rpc_bind_port);
    cryptonote::rpc_args::init_options(desc, true);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  core_rpc_server::core_rpc_server(
      core& cr
    , nodetool::node_server& p2p
    )
    : m_core(cr)
    , m_p2p(p2p)
  {}
  //------------------------------------------------------------------------------------------------------------------------------
  core_rpc_server::~core_rpc_server()
  {
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::init(
      const boost::program_options::variables_map& vm
      , const std::string& port
    )
  {
    m_net_server.set_threads_prefix("RPC");
    m_net_server.set_connection_filter(&m_p2p);

    auto rpc_config = cryptonote::rpc_args::process(vm, true);
    if (!rpc_config)
      return false;

    return epee::http_server_impl_base<core_rpc_server, connection_context>::init(
      std::move(port), std::move(rpc_config->bind_ip),
      std::move(rpc_config->bind_ipv6_address), std::move(rpc_config->use_ipv6), std::move(rpc_config->require_ipv4),
      std::move(rpc_config->access_control_origins), std::move(rpc_config->ssl_options)
    );
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::check_core_ready()
  {
    if(!m_p2p.get_payload_object().is_synchronized())
    {
      return false;
    }
    return true;
  }
#define CHECK_CORE_READY() do { if(!check_core_ready()){res.status =  CORE_RPC_STATUS_BUSY;return true;} } while(0)

  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_height(const COMMAND_RPC_GET_HEIGHT::request& req, COMMAND_RPC_GET_HEIGHT::response& res)
  {
    crypto::hash hash;
    m_core.get_blockchain_top(res.height, hash);
    ++res.height; // block height to chain height
    res.hash = epee::string_tools::pod_to_hex(hash);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_info(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res)
  {
    crypto::hash top_hash;
    m_core.get_blockchain_top(res.height, top_hash);
    ++res.height; // turn top block height into blockchain height
    res.top_block_hash = epee::string_tools::pod_to_hex(top_hash);
    res.target_height = m_p2p.get_payload_object().is_synchronized() ? 0 : m_core.get_target_blockchain_height();
    store_difficulty(m_core.get_blockchain_storage().get_difficulty_for_next_block(), res.difficulty, res.wide_difficulty, res.difficulty_top64);
    res.target = m_core.get_blockchain_storage().get_difficulty_target();
    res.tx_count = m_core.get_blockchain_storage().get_total_transactions() - res.height; //without coinbase
    res.tx_pool_size = m_core.get_pool_transactions_count(true);
    res.alt_blocks_count = m_core.get_blockchain_storage().get_alternative_blocks_count();
    uint64_t total_conn = m_p2p.get_public_connections_count();
    res.outgoing_connections_count = m_p2p.get_public_outgoing_connections_count();
    res.incoming_connections_count = (total_conn - res.outgoing_connections_count);
    res.rpc_connections_count = get_connections_count();
    res.white_peerlist_size = m_p2p.get_public_white_peers_count();
    res.grey_peerlist_size = m_p2p.get_public_gray_peers_count();

    cryptonote::network_type net_type = nettype();
    res.mainnet = net_type == MAINNET;
    res.testnet = net_type == TESTNET;
    res.nettype = net_type == MAINNET ? "mainnet" : net_type == TESTNET ? "testnet" : "fakechain";
    store_difficulty(m_core.get_blockchain_storage().get_db().get_block_cumulative_difficulty(res.height - 1),
        res.cumulative_difficulty, res.wide_cumulative_difficulty, res.cumulative_difficulty_top64);

    res.start_time = (uint64_t)m_core.get_start_time();
    res.free_space = m_core.get_free_space();
    res.offline = m_core.offline();
    res.database_size = m_core.get_blockchain_storage().get_db().get_database_size();
    res.version = LOLNERO_VERSION_FULL;
    res.busy_syncing = m_p2p.get_payload_object().is_busy_syncing();

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  class pruned_transaction {
    transaction& tx;
  public:
    pruned_transaction(transaction& tx) : tx(tx) {}
    BEGIN_SERIALIZE_OBJECT()
      bool r = tx.serialize_base(ar);
      if (!r) return false;
    END_SERIALIZE()
  };
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_blocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& req, COMMAND_RPC_GET_BLOCKS_FAST::response& res)
  {
    // quick check for noop
    if (!req.block_ids.empty())
    {
      uint64_t last_block_height;
      crypto::hash last_block_hash;
      m_core.get_blockchain_top(last_block_height, last_block_hash);
      if (last_block_hash == req.block_ids.front())
      {
        res.start_height = 0;
        res.current_height = m_core.get_current_blockchain_height();
        res.status = CORE_RPC_STATUS_OK;
        return true;
      }
    }

    constexpr size_t max_blocks = constant::COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT;

    std::vector<std::pair<std::pair<cryptonote::string_blob, crypto::hash>, std::vector<std::pair<crypto::hash, cryptonote::string_blob> > > > bs;
    if(!m_core.find_blockchain_supplement(req.start_height, req.block_ids, bs, res.current_height, res.start_height, !req.no_miner_tx, max_blocks))
    {
      res.status = "Failed";
      return false;
    }

    size_t size = 0, ntxes = 0;
    res.blocks.reserve(bs.size());
    res.output_indices.reserve(bs.size());
    for(auto& bd: bs)
    {
      res.blocks.resize(res.blocks.size()+1);
      res.blocks.back().pruned = req.prune;
      res.blocks.back().block = bd.first.first;
      size += bd.first.first.size();
      res.output_indices.push_back(COMMAND_RPC_GET_BLOCKS_FAST::block_output_indices());
      ntxes += bd.second.size();
      res.output_indices.back().indices.reserve(1 + bd.second.size());
      if (req.no_miner_tx)
        res.output_indices.back().indices.push_back(COMMAND_RPC_GET_BLOCKS_FAST::tx_output_indices());
      res.blocks.back().txs.reserve(bd.second.size());
      for (std::vector<std::pair<crypto::hash, cryptonote::string_blob>>::iterator i = bd.second.begin(); i != bd.second.end(); ++i)
      {
        res.blocks.back().txs.push_back({std::move(i->second), crypto::null_hash});
        i->second.clear();
        i->second.shrink_to_fit();
        size += res.blocks.back().txs.back().blob.size();
      }

      const size_t n_txes_to_lookup = bd.second.size() + (req.no_miner_tx ? 0 : 1);
      if (n_txes_to_lookup > 0)
      {
        std::vector<std::vector<uint64_t>> indices;
        bool r = m_core.get_tx_outputs_gindexs(req.no_miner_tx ? bd.second.front().first : bd.first.second, n_txes_to_lookup, indices);
        if (!r)
        {
          res.status = "Failed";
          return false;
        }
        if (indices.size() != n_txes_to_lookup || res.output_indices.back().indices.size() != (req.no_miner_tx ? 1 : 0))
        {
          res.status = "Failed";
          return false;
        }
        for (size_t i = 0; i < indices.size(); ++i)
          res.output_indices.back().indices.push_back({std::move(indices[i])});
      }
    }

    LOG_DEBUG("on_get_blocks: " << bs.size() << " blocks, " << ntxes << " txes, size " << size);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
    bool core_rpc_server::on_get_alt_blocks_hashes(const COMMAND_RPC_GET_ALT_BLOCKS_HASHES::request& req, COMMAND_RPC_GET_ALT_BLOCKS_HASHES::response& res)
    {
      std::vector<block> blks;

      if(!m_core.get_alternative_blocks(blks))
      {
          res.status = "Failed";
          return false;
      }

      res.blks_hashes.reserve(blks.size());

      for (auto const& blk: blks)
      {
          res.blks_hashes.push_back(epee::string_tools::pod_to_hex(get_block_hash(blk)));
      }

      LOG_DEBUG("on_get_alt_blocks_hashes: " << blks.size() << " blocks " );
      res.status = CORE_RPC_STATUS_OK;
      return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_hashes(const COMMAND_RPC_GET_HASHES_FAST::request& req, COMMAND_RPC_GET_HASHES_FAST::response& res)
  {
    res.start_height = req.start_height;
    if(!m_core.get_blockchain_storage().find_blockchain_supplement(req.block_ids, res.m_block_ids, NULL, res.start_height, res.current_height))
    {
      res.status = "Failed";
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_tx_outputs(const COMMAND_RPC_GET_OUTPUTS::request& req, COMMAND_RPC_GET_OUTPUTS::response& res)
  {
    res.status = "Failed";

    cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::request req_bin;
    req_bin.outputs = req.outputs;
    req_bin.get_txid = req.get_txid;
    cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::response res_bin;
    if(!m_core.get_tx_outputs(req_bin, res_bin))
    {
      return true;
    }

    // convert to text
    for (const auto &i: res_bin.outs)
    {
      res.outs.push_back(cryptonote::COMMAND_RPC_GET_OUTPUTS::outkey());
      cryptonote::COMMAND_RPC_GET_OUTPUTS::outkey &outkey = res.outs.back();
      outkey.key = epee::string_tools::pod_to_hex(i.key);
      outkey.mask = epee::string_tools::pod_to_hex(i.mask);
      outkey.unlocked = i.unlocked;
      outkey.height = i.height;
      if (req.get_txid)
        outkey.txid = epee::string_tools::pod_to_hex(i.txid);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res)
  {
    std::vector<crypto::hash> vh;
    for(const auto& tx_hex_str: req.txs_hashes)
    {
      string_blob b;
      if(!epee::string_tools::parse_hexstr_to_binbuff(tx_hex_str, b))
      {
        res.status = "Failed to parse hex representation of transaction hash";
        return true;
      }
      if(b.size() != sizeof(crypto::hash))
      {
        res.status = "Failed, size of data mismatch";
        return true;
      }
      vh.push_back(*reinterpret_cast<const crypto::hash*>(b.data()));
    }
    std::vector<crypto::hash> missed_txs;
    std::vector<std::pair<crypto::hash, cryptonote::string_blob>> txs;
    bool r = m_core.get_split_transactions_blobs(vh, txs, missed_txs);
    if(!r)
    {
      res.status = "Failed";
      return true;
    }
    LOG_PRINT_L2("Found " << txs.size() << "/" << vh.size() << " transactions on the blockchain");

    // try the pool for any missing txes
    size_t found_in_pool = 0;
    std::unordered_set<crypto::hash> pool_tx_hashes;
    std::unordered_map<crypto::hash, tx_info> per_tx_pool_tx_info;
    if (!missed_txs.empty())
    {
      std::vector<tx_info> pool_tx_info;
      std::vector<spent_output_key_image_info> pool_output_key_image_info;
      bool r = m_core.get_pool_transactions_and_spent_keys_info(pool_tx_info, pool_output_key_image_info, true);
      if(r)
      {
        // sort to match original request
        std::vector<std::pair<crypto::hash, cryptonote::string_blob>> sorted_txs;
        std::vector<tx_info>::const_iterator i;
        unsigned txs_processed = 0;
        for (const crypto::hash &h: vh)
        {
          if (std::find(missed_txs.begin(), missed_txs.end(), h) == missed_txs.end())
          {
            if (txs.size() == txs_processed)
            {
              res.status = "Failed: internal error - txs is empty";
              return true;
            }
            // core returns the ones it finds in the right order
            if (std::get<0>(txs[txs_processed]) != h)
            {
              res.status = "Failed: tx hash mismatch";
              return true;
            }
            sorted_txs.push_back(std::move(txs[txs_processed]));
            ++txs_processed;
          }
          else if ((i = std::find_if(pool_tx_info.begin(), pool_tx_info.end(), [h](const tx_info &txi) { return epee::string_tools::pod_to_hex(h) == txi.id_hash; })) != pool_tx_info.end())
          {
            const auto maybeTx = maybe_tx_from_blob(i->tx_blob);
            if (!maybeTx)
            {
              res.status = "Failed to parse and validate tx from blob";
              return true;
            }
            const cryptonote::transaction tx = *maybeTx;
            std::stringstream ss;
            binary_archive<true> ba(ss);
            bool r = const_cast<cryptonote::transaction&>(tx).serialize_base(ba);
            if (!r)
            {
              res.status = "Failed to serialize transaction base";
              return true;
            }
            sorted_txs.push_back(std::make_pair(h, i->tx_blob));
            missed_txs.erase(std::find(missed_txs.begin(), missed_txs.end(), h));
            pool_tx_hashes.insert(h);
            const std::string hash_string = epee::string_tools::pod_to_hex(h);
            for (const auto &ti: pool_tx_info)
            {
              if (ti.id_hash == hash_string)
              {
                per_tx_pool_tx_info.insert(std::make_pair(h, ti));
                break;
              }
            }
            ++found_in_pool;
          }
        }
        txs = sorted_txs;
      }
      LOG_PRINT_L2("Found " << found_in_pool << "/" << vh.size() << " transactions in the pool");
    }

    std::vector<std::string>::const_iterator txhi = req.txs_hashes.begin();
    std::vector<crypto::hash>::const_iterator vhi = vh.begin();
    for(auto& tx: txs)
    {
      res.txs.push_back(COMMAND_RPC_GET_TRANSACTIONS::entry());
      COMMAND_RPC_GET_TRANSACTIONS::entry &e = res.txs.back();

      crypto::hash tx_hash = *vhi++;
      e.tx_hash = *txhi++;
      {
        // use non-splitted form, leaving pruned_as_hex and prunable_as_hex as empty
        cryptonote::string_blob tx_data = std::get<1>(tx);
        e.as_hex = epee::string_tools::buff_to_hex_nodelimer(tx_data);
        if (req.decode_as_json)
        {
          cryptonote::transaction t;

          const auto maybeTx = maybe_tx_from_blob(tx_data);
          if (maybeTx)
          {
            e.as_json = obj_to_json_str(*maybeTx);
          }
          else
          {
            res.status = "Failed to parse and validate tx from blob";
            return true;
          }
        }
      }
      e.in_pool = pool_tx_hashes.find(tx_hash) != pool_tx_hashes.end();
      if (e.in_pool)
      {
        e.block_height = e.block_timestamp = std::numeric_limits<uint64_t>::max();
        auto it = per_tx_pool_tx_info.find(tx_hash);
        if (it != per_tx_pool_tx_info.end())
        {
          e.double_spend_seen = it->second.double_spend_seen;
          e.relayed = it->second.relayed;
          e.received_timestamp = it->second.receive_time;
        }
        else
        {
          LOG_ERROR("Failed to determine pool info for " << tx_hash);
          e.double_spend_seen = false;
          e.relayed = false;
          e.received_timestamp = 0;
        }
      }
      else
      {
        e.block_height = m_core.get_blockchain_storage().get_db().get_tx_block_height(tx_hash);
        e.block_timestamp = m_core.get_blockchain_storage().get_db().get_block_timestamp(e.block_height);
        e.received_timestamp = 0;
        e.double_spend_seen = false;
        e.relayed = false;
      }

      // output indices too if not in pool
      if (pool_tx_hashes.find(tx_hash) == pool_tx_hashes.end())
      {
        bool r = m_core.get_tx_outputs_gindexs(tx_hash, e.output_indices);
        if (!r)
        {
          res.status = "Failed";
          return false;
        }
      }
    }

    for(const auto& miss_tx: missed_txs)
    {
      res.missed_tx.push_back(epee::string_tools::pod_to_hex(miss_tx));
    }

    LOG_PRINT_L2(res.txs.size() << " transactions found, " << res.missed_tx.size() << " not found");
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_is_output_key_image_spent(const COMMAND_RPC_IS_KEY_IMAGE_SPENT::request& req, COMMAND_RPC_IS_KEY_IMAGE_SPENT::response& res)
  {
    std::vector<crypto::key_image> output_key_images;
    for(const auto& ki_hex_str: req.output_key_images)
    {
      string_blob b;
      if(!epee::string_tools::parse_hexstr_to_binbuff(ki_hex_str, b))
      {
        res.status = "Failed to parse hex representation of key image";
        return true;
      }
      if(b.size() != sizeof(crypto::key_image))
      {
        res.status = "Failed, size of data mismatch";
      }
      output_key_images.push_back(*reinterpret_cast<const crypto::key_image*>(b.data()));
    }
    std::vector<bool> spent_status;
    bool r = m_core.are_output_key_images_spent(output_key_images, spent_status);
    if(!r)
    {
      res.status = "Failed";
      return true;
    }
    res.spent_status.clear();
    for (size_t n = 0; n < spent_status.size(); ++n)
      res.spent_status.push_back(spent_status[n] ? COMMAND_RPC_IS_KEY_IMAGE_SPENT::SPENT_IN_BLOCKCHAIN : COMMAND_RPC_IS_KEY_IMAGE_SPENT::UNSPENT);

    // check the pool too
    std::vector<cryptonote::tx_info> txs;
    std::vector<cryptonote::spent_output_key_image_info> ki;
    r = m_core.get_pool_transactions_and_spent_keys_info(txs, ki, true);
    if(!r)
    {
      res.status = "Failed";
      return true;
    }
    for (std::vector<cryptonote::spent_output_key_image_info>::const_iterator i = ki.begin(); i != ki.end(); ++i)
    {
      const auto maybe_hash = parse_hash256(i->id_hash);
      crypto::key_image spent_output_key_image;
      if (maybe_hash)
      {
        const auto hash = *maybe_hash;
        memcpy(&spent_output_key_image, &hash, sizeof(hash)); // a bit dodgy, should be other parse functions somewhere
        for (size_t n = 0; n < res.spent_status.size(); ++n)
        {
          if (res.spent_status[n] == COMMAND_RPC_IS_KEY_IMAGE_SPENT::UNSPENT)
          {
            if (output_key_images[n] == spent_output_key_image)
            {
              res.spent_status[n] = COMMAND_RPC_IS_KEY_IMAGE_SPENT::SPENT_IN_POOL;
              break;
            }
          }
        }
      }
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_send_raw_tx(const COMMAND_RPC_SEND_RAW_TX::request& req, COMMAND_RPC_SEND_RAW_TX::response& res)
  {
    CHECK_CORE_READY();

    std::string tx_blob;
    if(!epee::string_tools::parse_hexstr_to_binbuff(req.tx_as_hex, tx_blob))
    {
      LOG_PRINT_L0("[on_send_raw_tx]: Failed to parse tx from hexbuff: " << req.tx_as_hex);
      res.status = "Failed";
      return true;
    }

    if (req.do_sanity_checks && !cryptonote::rct_tx_sanity_check(tx_blob, m_core.get_blockchain_storage().get_num_mature_outputs(0)))
    {
      res.status = "Failed";
      res.reason = "Sanity check failed";
      res.sanity_check_failed = true;
      return true;
    }
    res.sanity_check_failed = false;

    tx_verification_context tvc{};
    if(!m_core.handle_incoming_ringct({tx_blob, crypto::null_hash}, tvc, (req.do_not_relay ? relay_method::none : relay_method::local), false) || tvc.m_verifivation_failed)
    {
      res.status = "Failed";
      std::string reason = "";
      if ((res.low_mixin = tvc.m_low_mixin))
        add_reason(reason, "bad ring size");
      if ((res.double_spend = tvc.m_double_spend))
        add_reason(reason, "double spend");
      if ((res.invalid_input = tvc.m_invalid_input))
        add_reason(reason, "invalid input");
      if ((res.invalid_output = tvc.m_invalid_output))
        add_reason(reason, "invalid output");
      if ((res.too_big = tvc.m_too_big))
        add_reason(reason, "too big");
      if ((res.overspend = tvc.m_overspend))
        add_reason(reason, "overspend");
      if ((res.fee_too_low = tvc.m_fee_too_low))
        add_reason(reason, "fee too low");
      if ((res.too_few_outputs = tvc.m_too_few_outputs))
        add_reason(reason, "too few outputs");
      const std::string punctuation = reason.empty() ? "" : ": ";
      if (tvc.m_verifivation_failed)
      {
        LOG_PRINT_L0("[on_send_raw_tx]: tx verification failed" << punctuation << reason);
      }
      else
      {
        LOG_PRINT_L0("[on_send_raw_tx]: Failed to process tx" << punctuation << reason);
      }
      return true;
    }

    if(!tvc.m_should_be_relayed)
    {
      LOG_PRINT_L0("[on_send_raw_tx]: tx accepted, but not relayed");
      res.reason = "Not relayed";
      res.not_relayed = true;
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }

    NOTIFY_NEW_TRANSACTIONS::request r;
    r.txs.push_back(tx_blob);
    m_core.get_protocol()->relay_transactions(r, boost::uuids::nil_uuid(), epee::net_utils::zone::invalid);
    //TODO: make sure that tx has reached other nodes here, probably wait to receive reflections from other nodes
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_start_mining(const COMMAND_RPC_START_MINING::request& req, COMMAND_RPC_START_MINING::response& res)
  {
    CHECK_CORE_READY();
    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, nettype(), req.miner_address))
    {
      res.status = "Failed, wrong address";
      LOG_PRINT_L0(res.status);
      return true;
    }
    if (info.is_subaddress)
    {
      res.status = "Mining to subaddress isn't supported yet";
      LOG_PRINT_L0(res.status);
      return true;
    }

    unsigned int concurrency_count = std::thread::hardware_concurrency() * 4;

    // if we couldn't detect threads, set it to a ridiculously high number
    if(concurrency_count == 0)
    {
      concurrency_count = 257;
    }

    // if there are more threads requested than the hardware supports
    // then we fail and log that.
    if(req.threads_count > concurrency_count)
    {
      res.status = "Failed, too many threads relative to CPU cores.";
      LOG_PRINT_L0(res.status);
      return true;
    }

    cryptonote::miner &miner= m_core.get_miner();
    if (miner.is_mining())
    {
      res.status = "Already mining";
      return true;
    }
    if(!miner.start(info.address, static_cast<size_t>(req.threads_count)))
    {
      res.status = "Failed, mining not started";
      LOG_PRINT_L0(res.status);
      return true;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_stop_mining(const COMMAND_RPC_STOP_MINING::request& req, COMMAND_RPC_STOP_MINING::response& res)
  {
    cryptonote::miner &miner= m_core.get_miner();
    if(!miner.is_mining())
    {
      res.status = "Mining never started";
      LOG_PRINT_L0(res.status);
      return true;
    }
    if(!miner.stop())
    {
      res.status = "Failed, mining not stopped";
      LOG_PRINT_L0(res.status);
      return true;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_mining_status(const COMMAND_RPC_MINING_STATUS::request& req, COMMAND_RPC_MINING_STATUS::response& res)
  {
    const miner& lMiner = m_core.get_miner();
    res.active = lMiner.is_mining();
    store_difficulty(m_core.get_blockchain_storage().get_difficulty_for_next_block(), res.difficulty, res.wide_difficulty, res.difficulty_top64);

    res.block_target = DIFFICULTY_TARGET_IN_SECONDS;
    if ( lMiner.is_mining() ) {
      res.speed = lMiner.get_speed();
      res.threads_count = lMiner.get_threads_count();
      res.block_reward = lMiner.get_block_reward();
    }
    const spend_view_public_keys& lMiningAdr = lMiner.get_mining_address();
    if (lMiner.is_mining())
      res.address = get_account_address_as_str(nettype(), false, lMiningAdr);

    res.pow_algorithm = "SHA-3";
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_save_bc(const COMMAND_RPC_SAVE_BC::request& req, COMMAND_RPC_SAVE_BC::response& res)
  {
    if( !m_core.get_blockchain_storage().store_blockchain() )
    {
      res.status = "Error while storing blockchain";
      return true;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_peer_list(const COMMAND_RPC_GET_PEER_LIST::request& req, COMMAND_RPC_GET_PEER_LIST::response& res)
  {
    std::vector<nodetool::peerlist_entry> white_list;
    std::vector<nodetool::peerlist_entry> gray_list;

    if (req.public_only)
    {
      m_p2p.get_public_peerlist(gray_list, white_list);
    }
    else
    {
      m_p2p.get_peerlist(gray_list, white_list);
    }

    for (auto & entry : white_list)
    {
      if (entry.adr.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
        res.white_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv4_network_address>().ip(),
            entry.adr.as<epee::net_utils::ipv4_network_address>().port(), entry.last_seen);
      else if (entry.adr.get_type_id() == epee::net_utils::ipv6_network_address::get_type_id())
        res.white_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv6_network_address>().host_str(),
            entry.adr.as<epee::net_utils::ipv6_network_address>().port(), entry.last_seen);
      else
        res.white_list.emplace_back(entry.id, entry.adr.str(), entry.last_seen);
    }

    for (auto & entry : gray_list)
    {
      if (entry.adr.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
        res.gray_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv4_network_address>().ip(),
            entry.adr.as<epee::net_utils::ipv4_network_address>().port(), entry.last_seen);
      else if (entry.adr.get_type_id() == epee::net_utils::ipv6_network_address::get_type_id())
        res.gray_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv6_network_address>().host_str(),
            entry.adr.as<epee::net_utils::ipv6_network_address>().port(), entry.last_seen);
      else
        res.gray_list.emplace_back(entry.id, entry.adr.str(), entry.last_seen);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_log_level(const COMMAND_RPC_SET_LOG_LEVEL::request& req, COMMAND_RPC_SET_LOG_LEVEL::response& res)
  {
    if (req.level < 0 || req.level > 4)
    {
      res.status = "Error: log level not valid";
      return true;
    }
    epee::mlog_set_log_level(req.level);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transaction_pool(const COMMAND_RPC_GET_TRANSACTION_POOL::request& req, COMMAND_RPC_GET_TRANSACTION_POOL::response& res)
  {
    size_t n_txes = m_core.get_pool_transactions_count();
    if (n_txes > 0)
    {
      m_core.get_pool_transactions_and_spent_keys_info(res.transactions, res.spent_output_key_images);
      for (tx_info& txi : res.transactions)
        txi.tx_blob = epee::string_tools::buff_to_hex_nodelimer(txi.tx_blob);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transaction_pool_hashes(const COMMAND_RPC_GET_TRANSACTION_POOL_HASHES::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_HASHES::response& res)
  {
    size_t n_txes = m_core.get_pool_transactions_count();
    if (n_txes > 0)
    {
      std::vector<crypto::hash> tx_hashes;
      m_core.get_pool_transaction_hashes(tx_hashes);
      res.tx_hashes.reserve(tx_hashes.size());
      for (const crypto::hash &tx_hash: tx_hashes)
        res.tx_hashes.push_back(epee::string_tools::pod_to_hex(tx_hash));
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transaction_pool_stats(const COMMAND_RPC_GET_TRANSACTION_POOL_STATS::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_STATS::response& res)
  {
    m_core.get_pool_transaction_stats(res.pool_stats);

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_stop_daemon(const COMMAND_RPC_STOP_DAEMON::request& req, COMMAND_RPC_STOP_DAEMON::response& res)
  {
    // FIXME: replace back to original m_p2p.send_stop_signal() after
    // investigating why that isn't working quite right.
    m_p2p.send_stop_signal();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  // equivalent of strstr, but with arbitrary bytes (ie, NULs)
  // This does not differentiate between "not found" and "found at offset 0"
  size_t slow_memmem(const void* start_buff, size_t buflen,const void* pat,size_t patlen)
  {
    const void* buf = start_buff;
    const void* end=(const char*)buf+buflen;
    if (patlen > buflen || patlen == 0) return 0;
    while(buflen>0 && (buf=memchr(buf,((const char*)pat)[0],buflen-patlen+1)))
    {
      if(memcmp(buf,pat,patlen)==0)
        return (const char*)buf - (const char*)start_buff;
      buf=(const char*)buf+1;
      buflen = (const char*)end - (const char*)buf;
    }
    return 0;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  uint64_t core_rpc_server::get_block_reward(const block& blk)
  {
    uint64_t reward = 0;
    for(const tx_out& out: blk.miner_tx.vout)
    {
      reward += out.amount;
    }
    return reward;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::fill_block_header_response(const block& blk, bool orphan_status, uint64_t height, const crypto::hash& hash, block_header_response& response, bool fill_pow_hash)
  {
    response.major_version = blk.major_version;
    response.minor_version = blk.minor_version;
    response.timestamp = blk.timestamp;
    response.prev_hash = epee::string_tools::pod_to_hex(blk.prev_id);
    response.nonce = blk.nonce;
    response.orphan_status = orphan_status;
    response.height = height;
    response.depth = m_core.get_current_blockchain_height() - height - 1;
    response.hash = epee::string_tools::pod_to_hex(hash);
    store_difficulty(m_core.get_blockchain_storage().block_difficulty(height),
        response.difficulty, response.wide_difficulty, response.difficulty_top64);
    store_difficulty(m_core.get_blockchain_storage().get_db().get_block_cumulative_difficulty(height),
        response.cumulative_difficulty, response.wide_cumulative_difficulty, response.cumulative_difficulty_top64);
    response.reward = get_block_reward(blk);
    response.block_size = response.block_weight = m_core.get_blockchain_storage().get_db().get_block_weight(height);
    response.num_txes = blk.tx_hashes.size();
    response.pow_hash = fill_pow_hash ? epee::string_tools::pod_to_hex(get_mining_hash(blk)) : "";
    response.long_term_weight = m_core.get_blockchain_storage().get_db().get_block_long_term_weight(height);
    response.miner_tx_hash = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(blk.miner_tx));
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& res, epee::json_rpc::error& error_resp)
  {
    auto get = [this](const std::string &hash, bool fill_pow_hash, block_header_response &block_header, epee::json_rpc::error& error_resp) -> bool {
      crypto::hash block_hash;
      const auto maybe_hash = parse_hash256(hash);
      if(!maybe_hash)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Failed to parse hex representation of block hash. Hex = " + hash + '.';
        return false;
      }
      block blk;
      bool orphan = false;
      bool have_block = m_core.get_block_by_hash(block_hash, blk, &orphan);
      if (!have_block)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: can't get block by hash. Hash = " + hash + '.';
        return false;
      }
      if (blk.miner_tx.vin.size() != 1 || blk.miner_tx.vin.front().type() != typeid(txin_gen))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: coinbase transaction in the block has the wrong type";
        return false;
      }
      uint64_t block_height = boost::get<txin_gen>(blk.miner_tx.vin.front()).height;
      bool response_filled = fill_block_header_response(blk, orphan, block_height, block_hash, block_header, fill_pow_hash);
      if (!response_filled)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: can't produce valid response.";
        return false;
      }
      return true;
    };

    if (!req.hash.empty())
    {
      if (!get(req.hash, req.fill_pow_hash, res.block_header, error_resp))
        return false;
    }
    res.block_headers.reserve(req.hashes.size());
    for (const std::string &hash: req.hashes)
    {
      res.block_headers.push_back({});
      if (!get(hash, req.fill_pow_hash, res.block_headers.back(), error_resp))
        return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block_headers_range(const COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::request& req, COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::response& res, epee::json_rpc::error& error_resp)
  {
    const uint64_t bc_height = m_core.get_current_blockchain_height();
    if (req.start_height >= bc_height || req.end_height >= bc_height || req.start_height > req.end_height)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT;
      error_resp.message = "Invalid start/end heights.";
      return false;
    }

    for (uint64_t h = req.start_height; h <= req.end_height; ++h)
    {
      crypto::hash block_hash = m_core.get_block_id_by_height(h);
      block blk;
      bool have_block = m_core.get_block_by_hash(block_hash, blk);
      if (!have_block)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: can't get block by height. Height = " + boost::lexical_cast<std::string>(h) + ". Hash = " + epee::string_tools::pod_to_hex(block_hash) + '.';
        return false;
      }
      if (blk.miner_tx.vin.size() != 1 || blk.miner_tx.vin.front().type() != typeid(txin_gen))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: coinbase transaction in the block has the wrong type";
        return false;
      }
      uint64_t block_height = boost::get<txin_gen>(blk.miner_tx.vin.front()).height;
      if (block_height != h)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: coinbase transaction in the block has the wrong height";
        return false;
      }
      res.headers.push_back(block_header_response());
      bool response_filled = fill_block_header_response(blk, false, block_height, block_hash, res.headers.back(), req.fill_pow_hash);
      if (!response_filled)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: can't produce valid response.";
        return false;
      }
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block_header_by_height(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& res, epee::json_rpc::error& error_resp)
  {
    if(m_core.get_current_blockchain_height() <= req.height)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT;
      error_resp.message = std::string("Requested block height: ") + std::to_string(req.height) + " greater than current top block height: " +  std::to_string(m_core.get_current_blockchain_height() - 1);
      return false;
    }
    crypto::hash block_hash = m_core.get_block_id_by_height(req.height);
    block blk;
    bool have_block = m_core.get_block_by_hash(block_hash, blk);
    if (!have_block)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't get block by height. Height = " + std::to_string(req.height) + '.';
      return false;
    }
    bool response_filled = fill_block_header_response(blk, false, req.height, block_hash, res.block_header, req.fill_pow_hash);
    if (!response_filled)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't produce valid response.";
      return false;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block(const COMMAND_RPC_GET_BLOCK::request& req, COMMAND_RPC_GET_BLOCK::response& res, epee::json_rpc::error& error_resp)
  {
    crypto::hash block_hash;
    if (!req.hash.empty())
    {
      const auto maybe_hash = parse_hash256(req.hash);
      if(!maybe_hash)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Failed to parse hex representation of block hash. Hex = " + req.hash + '.';
        return false;
      }
      block_hash = *maybe_hash;
    }
    else
    {
      if(m_core.get_current_blockchain_height() <= req.height)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT;
        error_resp.message = std::string("Requested block height: ") + std::to_string(req.height) + " greater than current top block height: " +  std::to_string(m_core.get_current_blockchain_height() - 1);
        return false;
      }
      block_hash = m_core.get_block_id_by_height(req.height);
    }
    block blk;
    bool orphan = false;
    bool have_block = m_core.get_block_by_hash(block_hash, blk, &orphan);
    if (!have_block)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't get block by hash. Hash = " + req.hash + '.';
      return false;
    }
    if (blk.miner_tx.vin.size() != 1 || blk.miner_tx.vin.front().type() != typeid(txin_gen))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: coinbase transaction in the block has the wrong type";
      return false;
    }
    uint64_t block_height = boost::get<txin_gen>(blk.miner_tx.vin.front()).height;
    bool response_filled = fill_block_header_response(blk, orphan, block_height, block_hash, res.block_header, req.fill_pow_hash);
    if (!response_filled)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't produce valid response.";
      return false;
    }
    res.miner_tx_hash = res.block_header.miner_tx_hash;
    for (size_t n = 0; n < blk.tx_hashes.size(); ++n)
    {
      res.tx_hashes.push_back(epee::string_tools::pod_to_hex(blk.tx_hashes[n]));
    }
    res.blob = epee::string_tools::buff_to_hex_nodelimer(t_serializable_object_to_blob(blk));
    res.json = obj_to_json_str(blk);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_connections(const COMMAND_RPC_GET_CONNECTIONS::request& req, COMMAND_RPC_GET_CONNECTIONS::response& res, epee::json_rpc::error& error_resp)
  {
    res.connections = m_p2p.get_payload_object().get_connections();

    res.status = CORE_RPC_STATUS_OK;

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_info_json(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res, epee::json_rpc::error& error_resp)
  {
    if (!on_get_info(req, res) || res.status != CORE_RPC_STATUS_OK)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = res.status;
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_bans(const COMMAND_RPC_GETBANS::request& req, COMMAND_RPC_GETBANS::response& res, epee::json_rpc::error& error_resp)
  {
    auto now = time(nullptr);
    std::map<std::string, time_t> blocked_hosts = m_p2p.get_blocked_hosts();
    for (std::map<std::string, time_t>::const_iterator i = blocked_hosts.begin(); i != blocked_hosts.end(); ++i)
    {
      if (i->second > now) {
        COMMAND_RPC_GETBANS::ban b;
        b.host = i->first;
        b.ip = 0;
        uint32_t ip;
        if (epee::string_tools::get_ip_int32_from_string(ip, b.host))
          b.ip = ip;
        b.seconds = i->second - now;
        res.bans.push_back(b);
      }
    }
    std::map<epee::net_utils::ipv4_network_subnet, time_t> blocked_subnets = m_p2p.get_blocked_subnets();
    for (std::map<epee::net_utils::ipv4_network_subnet, time_t>::const_iterator i = blocked_subnets.begin(); i != blocked_subnets.end(); ++i)
    {
      if (i->second > now) {
        COMMAND_RPC_GETBANS::ban b;
        b.host = i->first.host_str();
        b.ip = 0;
        b.seconds = i->second - now;
        res.bans.push_back(b);
      }
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_banned(const COMMAND_RPC_BANNED::request& req, COMMAND_RPC_BANNED::response& res, epee::json_rpc::error& error_resp)
  {
    auto na_parsed = net::get_network_address(req.address, 0);
    if (!na_parsed)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Unsupported host type";
      return false;
    }
    epee::net_utils::network_address na = std::move(*na_parsed);

    time_t seconds;
    if (m_p2p.is_host_blocked(na, &seconds))
    {
      res.banned = true;
      res.seconds = seconds;
    }
    else
    {
      res.banned = false;
      res.seconds = 0;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_bans(const COMMAND_RPC_SETBANS::request& req, COMMAND_RPC_SETBANS::response& res, epee::json_rpc::error& error_resp)
  {
    for (auto i = req.bans.begin(); i != req.bans.end(); ++i)
    {
      epee::net_utils::network_address na;

      // try subnet first
      if (!i->host.empty())
      {
        auto ns_parsed = net::get_ipv4_subnet_address(i->host);
        if (ns_parsed)
        {
          if (i->ban)
            m_p2p.block_subnet(*ns_parsed, i->seconds);
          else
            m_p2p.unblock_subnet(*ns_parsed);
          continue;
        }
      }

      // then host
      if (!i->host.empty())
      {
        auto na_parsed = net::get_network_address(i->host, 0);
        if (!na_parsed)
        {
          error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
          error_resp.message = "Unsupported host/subnet type";
          return false;
        }
        na = std::move(*na_parsed);
      }
      else
      {
        na = epee::net_utils::ipv4_network_address{i->ip, 0};
      }
      if (i->ban)
        m_p2p.block_host(na, i->seconds);
      else
        m_p2p.unblock_host(na);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_flush_txpool(const COMMAND_RPC_FLUSH_TRANSACTION_POOL::request& req, COMMAND_RPC_FLUSH_TRANSACTION_POOL::response& res, epee::json_rpc::error& error_resp)
  {
    bool failed = false;
    std::vector<crypto::hash> txids;
    if (req.txids.empty())
    {
      std::vector<transaction> pool_txs;
      bool r = m_core.get_pool_transactions(pool_txs, true);
      if (!r)
      {
        res.status = "Failed to get txpool contents";
        return true;
      }
      for (const auto &tx: pool_txs)
      {
        txids.push_back(cryptonote::get_transaction_hash(tx));
      }
    }
    else
    {
      for (const auto &str: req.txids)
      {
        crypto::hash txid;
        if(!epee::string_tools::hex_to_pod(str, txid))
        {
          failed = true;
        }
        else
        {
          txids.push_back(txid);
        }
      }
    }
    if (!m_core.get_blockchain_storage().flush_txes_from_pool(txids))
    {
      res.status = "Failed to remove one or more tx(es)";
      return false;
    }

    if (failed)
    {
      if (txids.empty())
        res.status = "Failed to parse txid";
      else
        res.status = "Failed to parse some of the txids";
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_version(const COMMAND_RPC_GET_VERSION::request& req, COMMAND_RPC_GET_VERSION::response& res, epee::json_rpc::error& error_resp)
  {
    res.version = CORE_RPC_VERSION;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_coinbase_tx_sum(const COMMAND_RPC_GET_COINBASE_TX_SUM::request& req, COMMAND_RPC_GET_COINBASE_TX_SUM::response& res, epee::json_rpc::error& error_resp)
  {
    const uint64_t bc_height = m_core.get_current_blockchain_height();
    if (req.height >= bc_height || req.count > bc_height)
    {
      res.status = "height or count is too large";
      return true;
    }

    std::pair<boost::multiprecision::uint128_t, boost::multiprecision::uint128_t> amounts = m_core.get_coinbase_tx_sum(req.height, req.count);
    store_128(amounts.first, res.emission_amount, res.wide_emission_amount, res.emission_amount_top64);
    store_128(amounts.second, res.fee_amount, res.wide_fee_amount, res.fee_amount_top64);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_alternate_chains(const COMMAND_RPC_GET_ALTERNATE_CHAINS::request& req, COMMAND_RPC_GET_ALTERNATE_CHAINS::response& res, epee::json_rpc::error& error_resp)
  {
    try
    {
      std::vector<std::pair<Blockchain::block_extended_info, std::vector<crypto::hash>>> chains = m_core.get_blockchain_storage().get_alternative_chains();
      for (const auto &i: chains)
      {
        diff_t wdiff = i.first.cumulative_difficulty;
        res.chains.push_back(COMMAND_RPC_GET_ALTERNATE_CHAINS::chain_info{epee::string_tools::pod_to_hex(get_block_hash(i.first.bl)), i.first.height, i.second.size(), 0, "", 0, {}, std::string()});
        store_difficulty(wdiff, res.chains.back().difficulty, res.chains.back().wide_difficulty, res.chains.back().difficulty_top64);
        res.chains.back().block_hashes.reserve(i.second.size());
        for (const crypto::hash &block_id: i.second)
          res.chains.back().block_hashes.push_back(epee::string_tools::pod_to_hex(block_id));
        if (i.first.height < i.second.size())
        {
          res.status = "Error finding alternate chain attachment point";
          return true;
        }
        cryptonote::block main_chain_parent_block;
        try { main_chain_parent_block = m_core.get_blockchain_storage().get_db().get_block_from_height(i.first.height - i.second.size()); }
        catch (const std::exception &e) { res.status = "Error finding alternate chain attachment point"; return true; }
        res.chains.back().main_chain_parent_block = epee::string_tools::pod_to_hex(get_block_hash(main_chain_parent_block));
      }
      res.status = CORE_RPC_STATUS_OK;
    }
    catch (...)
    {
      res.status = "Error retrieving alternate chains";
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_out_peers(const COMMAND_RPC_OUT_PEERS::request& req, COMMAND_RPC_OUT_PEERS::response& res)
  {
    if (req.set)
      m_p2p.change_max_out_public_peers(req.out_peers);
    res.out_peers = m_p2p.get_max_out_public_peers();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_in_peers(const COMMAND_RPC_IN_PEERS::request& req, COMMAND_RPC_IN_PEERS::response& res)
  {
    if (req.set)
      m_p2p.change_max_in_public_peers(req.in_peers);
    res.in_peers = m_p2p.get_max_in_public_peers();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_pop_blocks(const COMMAND_RPC_POP_BLOCKS::request& req, COMMAND_RPC_POP_BLOCKS::response& res)
  {
    m_core.get_blockchain_storage().pop_blocks(req.nblocks);

    res.height = m_core.get_current_blockchain_height();
    res.status = CORE_RPC_STATUS_OK;

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_relay_tx(const COMMAND_RPC_RELAY_TX::request& req, COMMAND_RPC_RELAY_TX::response& res, epee::json_rpc::error& error_resp)
  {
    bool failed = false;
    res.status = "";
    for (const auto &str: req.txids)
    {
      crypto::hash txid;
      if(!epee::string_tools::hex_to_pod(str, txid))
      {
        if (!res.status.empty()) res.status += ", ";
        res.status += std::string("invalid transaction id: ") + str;
        failed = true;
        continue;
      }

      cryptonote::string_blob txblob;
      if (m_core.get_pool_transaction(txid, txblob, relay_category::legacy))
      {
        NOTIFY_NEW_TRANSACTIONS::request r;
        r.txs.push_back(txblob);
        m_core.get_protocol()->relay_transactions(r, boost::uuids::nil_uuid(), epee::net_utils::zone::invalid);
        //TODO: make sure that tx has reached other nodes here, probably wait to receive reflections from other nodes
      }
      else
      {
        if (!res.status.empty()) res.status += ", ";
        res.status += std::string("transaction not found in pool: ") + str;
        failed = true;
        continue;
      }
    }

    if (failed)
    {
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_sync_info(const COMMAND_RPC_SYNC_INFO::request& req, COMMAND_RPC_SYNC_INFO::response& res, epee::json_rpc::error& error_resp)
  {
    crypto::hash top_hash;
    m_core.get_blockchain_top(res.height, top_hash);
    ++res.height; // turn top block height into blockchain height
    res.target_height = m_p2p.get_payload_object().is_synchronized() ? 0 : m_core.get_target_blockchain_height();

    for (const auto &c: m_p2p.get_payload_object().get_connections())
      res.peers.push_back({c});
    const cryptonote::block_queue &block_queue = m_p2p.get_payload_object().get_block_queue();
    block_queue.foreach([&](const cryptonote::block_queue::span &span) {
      const std::string span_connection_id = epee::string_tools::pod_to_hex(span.connection_id);
      uint32_t speed = (uint32_t)(100.0f * block_queue.get_speed(span.connection_id) + 0.5f);
      res.spans.push_back({span.start_block_height, span.nblocks, span_connection_id, (uint32_t)(span.rate + 0.5f), speed, span.size, span.origin.str()});
      return true;
    });
    res.overview = block_queue.get_overview(res.height);

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_output_distribution(const COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::request& req, COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::response& res, epee::json_rpc::error& error_resp)
  {
    size_t n_0 = 0, n_non0 = 0;
    for (uint64_t amount: req.amounts)
      if (amount) ++n_non0; else ++n_0;
    try
    {
      // 0 is placeholder for the whole chain
      const uint64_t req_to_height = req.to_height ? req.to_height : (m_core.get_current_blockchain_height() - 1);
      for (uint64_t amount: req.amounts)
      {
        auto data = rpc::RpcHandler::get_output_distribution([this](uint64_t amount, uint64_t from, uint64_t to, uint64_t &start_height, std::vector<uint64_t> &distribution, uint64_t &base) { return m_core.get_output_distribution(amount, from, to, start_height, distribution, base); }, amount, req.from_height, req_to_height, [this](uint64_t height) { return m_core.get_blockchain_storage().get_db().get_block_hash_from_height(height); }, req.cumulative, m_core.get_current_blockchain_height());
        if (!data)
        {
          error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
          error_resp.message = "Failed to get output distribution";
          return false;
        }

        res.distributions.push_back({std::move(*data), amount});
      }
    }
    catch (const std::exception &e)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Failed to get output distribution";
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_flush_cache(const COMMAND_RPC_FLUSH_CACHE::request& req, COMMAND_RPC_FLUSH_CACHE::response& res, epee::json_rpc::error& error_resp)
  {
    if (req.bad_txs)
      m_core.flush_bad_txs_cache();
    if (req.bad_blocks)
      m_core.flush_invalid_blocks();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  const command_line::arg_descriptor<std::string, false, true, 1> core_rpc_server::arg_rpc_bind_port = {
    "rpc-bind-port"
    , "Port for RPC server"
    , std::to_string(cryptonote::mainnet.RPC_DEFAULT_PORT)
    , arg_testnet_on
    , [](bool testnet, bool defaulted, std::string val)->std::string {
      if (testnet && defaulted)
        return std::to_string(cryptonote::testnet.RPC_DEFAULT_PORT);
      return val;
    }
  };
}  // namespace cryptonote
