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

#include <cstdint>
#include <optional>
#include <vector>

#include "cryptonote/tx/cryptonote_tx_utils.h" // tx_destination_entry
#include "cryptonote/basic/fwd.h" // transaction
#include "network/rpc/core_rpc_server_commands_defs.h" // COMMAND_RPC_SEND_RAW_TX, backlog_entry

#include "wallet/logic/type/transfer.hpp" // tranfser_details

using namespace wallet::logic::type::transfer;

namespace wallet {
namespace logic {
namespace functional {
namespace wallet {

  constexpr uint64_t estimate_blockchain_height
  (
   const uint64_t approximate_height
   , const std::optional<uint64_t> target_height
   , const std::optional<uint64_t> local_height
   )
  {
    // ~num blocks per month
    const uint64_t blocks_per_month = 288*30;

    uint64_t height = approximate_height;

    // we get the max of approximated height and local height.
    // approximated height is the least of daemon target height
    // (the max of what the other daemons are claiming is their
    // height) and the theoretical height based on the local
    // clock. This will be wrong only if both the local clock
    // is bad *and* a peer daemon claims a highest height than
    // the real chain.
    // local height is the height the local daemon is currently
    // synced to, it will be lower than the real chain height if
    // the daemon is currently syncing.
    // If we use the approximate height we subtract one month as
    // a safety margin.

    if (target_height) {
      if (target_height.value() < height)
        height = target_height.value();
    } else {
      // if we couldn't talk to the daemon, check safety margin.
      if (height > blocks_per_month)
        height -= blocks_per_month;
      else
        height = 0;
    }
    if (local_height) {
      if (local_height.value() > height) {
        height = local_height.value();
      }
    }
    return height;
  }

  size_t get_num_outputs
  (
   const std::vector<cryptonote::tx_destination_entry> &dsts
   , const std::vector<::wallet::logic::type::transfer::transfer_details> &transfers
   , const std::vector<size_t> &selected_transfers
   );

  std::string get_text_reason(const cryptonote::COMMAND_RPC_SEND_RAW_TX::response &res);

  std::string get_weight_string(const size_t weight);

  std::string get_weight_string(const cryptonote::transaction &tx, const size_t blob_size);

  constexpr uint32_t get_subaddress_clamped_sum(const uint32_t idx, const uint32_t extra)
  {
    constexpr uint32_t uint32_max = std::numeric_limits<uint32_t>::max();
    if (idx > uint32_max - extra)
      return uint32_max;
    return idx + extra;
  }

  float get_output_relatedness(const transfer_details& td0, const transfer_details& td1);

  std::vector<std::pair<uint64_t, uint64_t>> estimate_backlog
  (
   const uint64_t height
   , const std::vector<cryptonote::tx_backlog_entry>& backlog
   , const std::vector<std::pair<double, double>>& fee_levels
   );

} // wallet
} // functional
} // logic
} // wallet
