// Copyright (c) 2021, The Lolnero Project
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

#include "transfer.hpp"
#include "tx.hpp"

#include "network/rpc/core_rpc_server_commands_defs.h" //block_outptu_indices



namespace wallet {
namespace logic {
namespace type {
namespace wallet {

  using transfer_container = std::vector<transfer::transfer_details>;
  using transfer_container_span = std::span<const transfer::transfer_details>;

  // The term "Unsigned tx" is not really a tx since it's not signed yet.
  // It doesnt have tx hash, key and the integrated address is not separated into addr + payment id.
  struct unsigned_tx_set
  {
    std::vector<::wallet::logic::type::tx::tx_construction_data> txes;
    std::pair<size_t, transfer_container> transfers;

    BEGIN_SERIALIZE_OBJECT()
    VERSION_FIELD(0)
    FIELD(txes)
    FIELD(transfers)
    END_SERIALIZE()
  };

  struct signed_tx_set
  {
    std::vector<::wallet::logic::type::tx::pending_tx> ptx;
    std::vector<crypto::key_image> output_key_images;
    serializable_unordered_map<crypto::public_key, crypto::key_image> tx_output_output_key_images;

    BEGIN_SERIALIZE_OBJECT()
    VERSION_FIELD(0)
    FIELD(ptx)
    FIELD(output_key_images)
    FIELD(tx_output_output_key_images)
    END_SERIALIZE()
  };

  struct keys_file_data
  {
    crypto::chacha_iv iv;
    std::string account_data;

    BEGIN_SERIALIZE_OBJECT()
    FIELD(iv)
    FIELD(account_data)
    END_SERIALIZE()
  };

  struct cache_file_data
  {
    crypto::chacha_iv iv;
    std::string cache_data;

    BEGIN_SERIALIZE_OBJECT()
    FIELD(iv)
    FIELD(cache_data)
    END_SERIALIZE()
  };

  struct parsed_block
  {
    crypto::hash hash;
    cryptonote::block block;
    std::vector<cryptonote::transaction> txes;
    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::block_output_indices o_indices;
    bool error;
  };

} // wallet
} // type
} // logic
} // wallet
