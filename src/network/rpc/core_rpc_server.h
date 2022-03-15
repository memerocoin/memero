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

#pragma  once


#include "cryptonote/core/cryptonote_core.h"
#include "cryptonote/protocol/cryptonote_protocol_handler.h"

#include "network/p2p/net_node.h"

#include "tools/epee/include/net/http_server_impl_base.h"
#include "tools/epee/include/net/http_server_handlers_map2.h"


namespace cryptonote
{
  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  class core_rpc_server: public epee::http_server_impl_base<core_rpc_server>
  {
  public:

    typedef epee::net_utils::connection_context_base connection_context;

    core_rpc_server
    (
     core& cr
     , nodetool::node_server& p2p
     );
    ~core_rpc_server();

    static void init_options(boost::program_options::options_description& desc);
    bool init
    (
     const boost::program_options::variables_map& vm,
     const std::string& port
     );
    network_type nettype() const { return m_core.get_nettype(); }

    CHAIN_HTTP_TO_MAP2(connection_context); //forward http requests to uri map

    BEGIN_URI_MAP2()

        MAP_URI_AUTO_JON2("/get_blocks", on_get_blocks, COMMAND_RPC_GET_BLOCKS_FAST)
        MAP_URI_AUTO_JON2("/get_hashes", on_get_hashes, COMMAND_RPC_GET_HASHES_FAST)

        MAP_URI_AUTO_JON2("/is_output_key_image_spent", on_is_output_key_image_spent, COMMAND_RPC_IS_KEY_IMAGE_SPENT)
        MAP_URI_AUTO_JON2("/send_raw_transaction", on_send_raw_tx, COMMAND_RPC_SEND_RAW_TX)
        MAP_URI_AUTO_JON2("/start_mining", on_start_mining, COMMAND_RPC_START_MINING)
        MAP_URI_AUTO_JON2("/stop_mining", on_stop_mining, COMMAND_RPC_STOP_MINING)
        MAP_URI_AUTO_JON2("/mining_status", on_mining_status, COMMAND_RPC_MINING_STATUS)
        MAP_URI_AUTO_JON2("/get_peer_list", on_get_peer_list, COMMAND_RPC_GET_PEER_LIST)
        MAP_URI_AUTO_JON2("/get_transaction_pool", on_get_transaction_pool, COMMAND_RPC_GET_TRANSACTION_POOL)
        MAP_URI_AUTO_JON2("/get_transaction_pool_hashes", on_get_transaction_pool_hashes, COMMAND_RPC_GET_TRANSACTION_POOL_HASHES)
        MAP_URI_AUTO_JON2("/get_info", on_get_info, COMMAND_RPC_GET_INFO)
        MAP_URI_AUTO_JON2("/get_tx_outputs", on_get_tx_outputs, COMMAND_RPC_GET_OUTPUTS)
        MAP_URI_AUTO_JON2("/pop_blocks", on_pop_blocks, COMMAND_RPC_POP_BLOCKS)

        MAP_URI_AUTO_JON2("/get_transactions", on_get_transactions, COMMAND_RPC_GET_TRANSACTIONS)

        BEGIN_JSON_RPC_MAP("/json_rpc")

            MAP_JON_RPC_WE("get_block_header_by_hash", on_get_block_header_by_hash, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH)
            MAP_JON_RPC_WE("get_block_header_by_height", on_get_block_header_by_height, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT)
            MAP_JON_RPC_WE("get_block", on_get_block, COMMAND_RPC_GET_BLOCK)
            MAP_JON_RPC_WE("get_connections",on_get_connections, COMMAND_RPC_GET_CONNECTIONS)
            MAP_JON_RPC_WE("get_info", on_get_info_json, COMMAND_RPC_GET_INFO)
            MAP_JON_RPC_WE("set_bans", on_set_bans, COMMAND_RPC_SETBANS)
            MAP_JON_RPC_WE("get_bans", on_get_bans, COMMAND_RPC_GETBANS)
            MAP_JON_RPC_WE("banned", on_banned, COMMAND_RPC_BANNED)
            MAP_JON_RPC_WE("flush_txpool", on_flush_txpool, COMMAND_RPC_FLUSH_TRANSACTION_POOL)
            MAP_JON_RPC_WE("get_version", on_get_version, COMMAND_RPC_GET_VERSION)
            MAP_JON_RPC_WE("get_coinbase_tx_sum", on_get_coinbase_tx_sum, COMMAND_RPC_GET_COINBASE_TX_SUM)
            MAP_JON_RPC_WE("relay_tx", on_relay_tx, COMMAND_RPC_RELAY_TX)
            MAP_JON_RPC_WE("sync_info", on_sync_info, COMMAND_RPC_SYNC_INFO)
            MAP_JON_RPC_WE("get_output_distribution", on_get_output_distribution, COMMAND_RPC_GET_OUTPUT_DISTRIBUTION)
            MAP_JON_RPC_WE("flush_cache", on_flush_cache, COMMAND_RPC_FLUSH_CACHE)

        END_JSON_RPC_MAP()

    END_URI_MAP2()

    bool on_get_blocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& req, COMMAND_RPC_GET_BLOCKS_FAST::response& res);
    bool on_get_hashes(const COMMAND_RPC_GET_HASHES_FAST::request& req, COMMAND_RPC_GET_HASHES_FAST::response& res);
    bool on_get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res);
    bool on_is_output_key_image_spent(const COMMAND_RPC_IS_KEY_IMAGE_SPENT::request& req, COMMAND_RPC_IS_KEY_IMAGE_SPENT::response& res);
    bool on_send_raw_tx(const COMMAND_RPC_SEND_RAW_TX::request& req, COMMAND_RPC_SEND_RAW_TX::response& res);
    bool on_start_mining(const COMMAND_RPC_START_MINING::request& req, COMMAND_RPC_START_MINING::response& res);
    bool on_stop_mining(const COMMAND_RPC_STOP_MINING::request& req, COMMAND_RPC_STOP_MINING::response& res);
    bool on_mining_status(const COMMAND_RPC_MINING_STATUS::request& req, COMMAND_RPC_MINING_STATUS::response& res);
    bool on_get_tx_outputs(const COMMAND_RPC_GET_OUTPUTS::request& req, COMMAND_RPC_GET_OUTPUTS::response& res);
    bool on_get_info(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res);
    bool on_get_peer_list(const COMMAND_RPC_GET_PEER_LIST::request& req, COMMAND_RPC_GET_PEER_LIST::response& res);
    bool on_get_transaction_pool(const COMMAND_RPC_GET_TRANSACTION_POOL::request& req, COMMAND_RPC_GET_TRANSACTION_POOL::response& res);
    bool on_get_transaction_pool_hashes(const COMMAND_RPC_GET_TRANSACTION_POOL_HASHES::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_HASHES::response& res);
    bool on_pop_blocks(const COMMAND_RPC_POP_BLOCKS::request& req, COMMAND_RPC_POP_BLOCKS::response& res);

    //json_rpc
    bool on_get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& res, epee::json_rpc::error& error_resp);
    bool on_get_block_header_by_height(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& res, epee::json_rpc::error& error_resp);
    bool on_get_block(const COMMAND_RPC_GET_BLOCK::request& req, COMMAND_RPC_GET_BLOCK::response& res, epee::json_rpc::error& error_resp);
    bool on_get_connections(const COMMAND_RPC_GET_CONNECTIONS::request& req, COMMAND_RPC_GET_CONNECTIONS::response& res, epee::json_rpc::error& error_resp);
    bool on_get_info_json(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res, epee::json_rpc::error& error_resp);
    bool on_set_bans(const COMMAND_RPC_SETBANS::request& req, COMMAND_RPC_SETBANS::response& res, epee::json_rpc::error& error_resp);
    bool on_get_bans(const COMMAND_RPC_GETBANS::request& req, COMMAND_RPC_GETBANS::response& res, epee::json_rpc::error& error_resp);
    bool on_banned(const COMMAND_RPC_BANNED::request& req, COMMAND_RPC_BANNED::response& res, epee::json_rpc::error& error_resp);
    bool on_flush_txpool(const COMMAND_RPC_FLUSH_TRANSACTION_POOL::request& req, COMMAND_RPC_FLUSH_TRANSACTION_POOL::response& res, epee::json_rpc::error& error_resp);
    bool on_get_version(const COMMAND_RPC_GET_VERSION::request& req, COMMAND_RPC_GET_VERSION::response& res, epee::json_rpc::error& error_resp);
    bool on_get_coinbase_tx_sum(const COMMAND_RPC_GET_COINBASE_TX_SUM::request& req, COMMAND_RPC_GET_COINBASE_TX_SUM::response& res, epee::json_rpc::error& error_resp);
    bool on_relay_tx(const COMMAND_RPC_RELAY_TX::request& req, COMMAND_RPC_RELAY_TX::response& res, epee::json_rpc::error& error_resp);
    bool on_sync_info(const COMMAND_RPC_SYNC_INFO::request& req, COMMAND_RPC_SYNC_INFO::response& res, epee::json_rpc::error& error_resp);
    bool on_get_output_distribution(const COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::request& req, COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::response& res, epee::json_rpc::error& error_resp);
    bool on_flush_cache(const COMMAND_RPC_FLUSH_CACHE::request& req, COMMAND_RPC_FLUSH_CACHE::response& res, epee::json_rpc::error& error_resp);
    //-----------------------

  private:
    //utils
    uint64_t get_block_reward(const block& blk);
    bool fill_block_header_response(const block& blk, bool orphan_status, uint64_t height, const crypto::hash& hash, block_header_response& response, bool fill_pow_hash);
    enum invoke_http_mode { JON, BIN, JON_RPC };
    bool get_block_template
    (
     const spend_view_public_keys &address
     , const crypto::hash *prev_block
     , cryptonote::diff_t &difficulty
     , uint64_t &expected_reward
     , block &b
     , epee::json_rpc::error &error_resp
     );

    core& m_core;
    nodetool::node_server& m_p2p;
    std::recursive_mutex m_host_fails_score_lock;
    std::map<std::string, uint64_t> m_host_fails_score;
  };
}
