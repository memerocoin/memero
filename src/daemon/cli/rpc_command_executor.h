/**
@file
@details

@image html images/other/runtime-commands.png

*/

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

#pragma once

#include "cryptonote/functional/helper.hpp"

#include "tools/common/rpc_client.h"

namespace daemonize {

class t_rpc_command_executor final {
private:
  std::unique_ptr<tools::t_rpc_client> m_rpc_client;
  bool m_is_rpc = true;

public:
  t_rpc_command_executor(
      uint32_t ip
    , uint16_t port
    );

  ~t_rpc_command_executor();

  bool print_peer_list(bool white = true, bool gray = true, size_t limit = 0);

  bool show_difficulty();

  bool show_status();

  bool print_connections();

  bool set_log_level(int8_t level);

  bool print_block_by_hash(crypto::hash block_hash, bool include_hex);

  bool print_block_by_height(uint64_t height, bool include_hex);

  bool print_transaction(crypto::hash transaction_hash, bool include_metadata, bool include_hex, bool include_json);

  bool is_output_key_image_spent(const crypto::key_image &ki);

  bool print_transaction_pool_long();

  bool print_transaction_pool_short();

  bool start_mining(cryptonote::spend_view_public_keys address, uint64_t num_threads, cryptonote::network_type nettype);

  bool stop_mining();

  bool mining_status();

  bool print_bans();

  bool ban(const std::string &address, time_t seconds);

  bool unban(const std::string &address);

  bool banned(const std::string &address);

  bool flush_txpool(const std::string &txid);

  bool print_coinbase_tx_sum(uint64_t height, uint64_t count);

  bool update(const std::string &command);

  bool relay_tx(const std::string &txid);

  bool sync_info();

  bool pop_blocks(uint64_t num_blocks);

  bool version();

  bool flush_cache(bool bad_txs, bool invalid_blocks);
};

} // namespace daemonize
