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


#include "wallet.hpp"

#include "cryptonote/functional/helper.hpp"

#include <string>



namespace wallet {
namespace logic {
namespace functional {
namespace wallet {

  size_t get_num_outputs
  (
   const std::vector<cryptonote::tx_destination_entry> &dsts
   , const std::vector<::wallet::logic::type::transfer::transfer_details> &transfers
   , const std::vector<size_t> &selected_transfers
   )
  {
    size_t outputs = dsts.size();
    uint64_t needed_money = 0;
    for (const auto& dt: dsts)
      needed_money += dt.amount;
    uint64_t found_money = 0;
    for(size_t idx: selected_transfers)
      found_money += transfers[idx].amount();
    if (found_money != needed_money)
      ++outputs; // change
    if (outputs < 2)
      ++outputs; // extra 0 dummy output
    return outputs;
  }

  std::string add_reason(std::string &reasons, std::string reason)
  {
    if (!reasons.empty())
      return reasons + ", ";
    return reasons + reason;
  }

  std::string get_text_reason(const cryptonote::COMMAND_RPC_SEND_RAW_TX::response &res)
  {
      std::string reason;
      if (res.low_mixin)
        reason = add_reason(reason, "bad ring size");
      if (res.double_spend)
        reason = add_reason(reason, "double spend");
      if (res.invalid_input)
        reason = add_reason(reason, "invalid input");
      if (res.invalid_output)
        reason = add_reason(reason, "invalid output");
      if (res.too_few_outputs)
        reason = add_reason(reason, "too few outputs");
      if (res.too_big)
        reason = add_reason(reason, "too big");
      if (res.overspend)
        reason = add_reason(reason, "overspend");
      if (res.fee_too_low)
        reason = add_reason(reason, "fee too low");
      if (res.sanity_check_failed)
        reason = add_reason(reason, "tx sanity check failed");
      if (res.not_relayed)
        reason = add_reason(reason, "tx was not relayed");
      return reason;
  }

  std::string get_weight_string(const size_t weight)
  {
    return std::to_string(weight) + " weight";
  }

  std::string get_weight_string(const cryptonote::transaction &tx, const size_t blob_size)
  {
    return get_weight_string(get_transaction_weight(tx, blob_size));
  }

  //----------------------------------------------------------------------------------------------------
  // This returns a handwavy estimation of how much two outputs are related
  // If they're from the same tx, then they're fully related. From close block
  // heights, they're kinda related. The actual values don't matter, just
  // their ordering, but it could become more murky if we add scores later.
  float get_output_relatedness(const transfer_details& td0, const transfer_details& td1)
  {
    // expensive test, and same tx will fall onto the same block height below
    if (td0.m_txid == td1.m_txid)
      return 1.0f;

    // same block height -> possibly tx burst, or same tx (since above is disabled)
    const int dh = td0.m_block_height > td1.m_block_height ?
      td0.m_block_height - td1.m_block_height :
      td1.m_block_height - td0.m_block_height;

    if (dh == 0)
      return 0.9f;

    // adjacent blocks -> possibly tx burst
    if (dh == 1)
      return 0.8f;

    // could extract the payment id, and compare them, but this is a bit expensive too

    // similar block heights
    if (dh < 10)
      return 0.2f;

    // don't think these are particularly related
    return 0.0f;
  }

  //----------------------------------------------------------------------------------------------------
  std::vector<std::pair<uint64_t, uint64_t>> estimate_backlog
  (
   const uint64_t height
   , const std::vector<cryptonote::tx_backlog_entry>& backlog
   , const std::vector<std::pair<double, double>>& fee_levels
   )
  {
    const uint64_t block_weight_limit = cryptonote::get_max_block_weight(height);
    const uint64_t full_reward_zone = block_weight_limit / 2;

    std::vector<std::pair<uint64_t, uint64_t>> blocks;
    for (const auto &fee_level: fee_levels)
    {
      const double our_fee_byte_min = fee_level.first;
      const double our_fee_byte_max = fee_level.second;
      uint64_t priority_weight_min = 0, priority_weight_max = 0;
      for (const auto &i: backlog)
      {
        if (i.weight == 0)
        {
          MWARNING("Got 0 weight tx from txpool, ignored");
          continue;
        }
        const double this_fee_byte = i.fee / (double)i.weight;
        if (this_fee_byte >= our_fee_byte_min)
          priority_weight_min += i.weight;
        if (this_fee_byte >= our_fee_byte_max)
          priority_weight_max += i.weight;
      }

      const uint64_t nblocks_min = priority_weight_min / full_reward_zone;
      const uint64_t nblocks_max = priority_weight_max / full_reward_zone;
      MDEBUG("estimate_backlog: priority_weight " << priority_weight_min << " - " << priority_weight_max << " for "
          << our_fee_byte_min << " - " << our_fee_byte_max << " piconero byte fee, "
          << nblocks_min << " - " << nblocks_max << " blocks at block weight " << full_reward_zone);
      blocks.push_back(std::make_pair(nblocks_min, nblocks_max));
    }
    return blocks;
  }

} // wallet
} // functional
} // logic
} // wallet
