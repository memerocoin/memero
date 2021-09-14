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

#include "math/ringct/pseudo_functional/rctSigs.hpp"

#include "cryptonote/basic/cryptonote_format_utils.h"

#include "wallet/api/wallet_errors.h"

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

  std::pair<std::set<uint64_t>, size_t> outs_unique(const std::vector<std::vector<::wallet::logic::type::get_outs_entry>> outs)
  {
    std::set<uint64_t> unique;
    size_t total = 0;

    for (const auto &it : outs)
      {
        for (const auto &out : it)
          {
            const uint64_t global_index = std::get<0>(out);
            unique.insert(global_index);
          }
        total += it.size();
      }

    return std::make_pair(std::move(unique), total);
  }

  //----------------------------------------------------------------------------------------------------
  type::tx::tx_scan_info_t check_acc_out_precomp
  (
   const cryptonote::tx_out o
   , const std::optional<crypto::tx_ecdh_shared_secret> tx_output_shared_secret
   , const size_t i
   , const serializable_unordered_map<crypto::public_key, cryptonote::subaddress_index>& m_subaddresses
   )
  {
    type::tx::tx_scan_info_t tx_scan_info;

    if (o.target.type() !=  typeid(cryptonote::txout_to_key))
    {
      tx_scan_info.error = true;
      LOG_ERROR("wrong type id in transaction out");
      return tx_scan_info;
    }

    // const auto secret
    //   = tx_output_shared_secrets.contains(i)
    //   ? tx_output_shared_secrets.at(i)
    //   : std::optional<crypto::tx_ecdh_shared_secret>();

    tx_scan_info.received = is_out_to_acc_precomp
      (
       m_subaddresses
       , boost::get<cryptonote::txout_to_key>(o.target).shared_secret_derived_public_key
       , {}
       , tx_output_shared_secret
       , i
       );
    if(tx_scan_info.received)
      {
        tx_scan_info.money_transfered = o.amount; // may be 0 for ringct outputs
      }
    else
      {
        tx_scan_info.money_transfered = 0;
      }
    tx_scan_info.error = false;

    return tx_scan_info;
  }

  //----------------------------------------------------------------------------------------------------
  std::optional<std::pair<uint64_t, rct::rct_scalar>> decodeRct
  (
   const rct::rctData rv
   , const crypto::tx_ecdh_shared_secret tx_shared_secret
   , const unsigned int i
   )
  {
    const crypto::ec_scalar s_der = crypto::hash_tx_shared_secret_to_scalar(tx_shared_secret, i);
    try
    {
      switch (rv.type)
        {
        case rct::RCTTypeCLSAG: {
          return {rct::decode_ringct_commitment(rv, rct::s2s(s_der), i)};
        }
        default:
          LOG_ERROR("Unsupported rct type: " << rv.type);
          return {};
        }
    }
    catch (const std::exception &e)
    {
      LOG_ERROR("Failed to decode input " << i);
      return {};
    }
  }

  //----------------------------------------------------------------------------------------------------
  type::tx::tx_scan_info_t scan_output
  (
   const cryptonote::transaction &tx
   , const bool miner_tx
   , const size_t i
   , const type::tx::tx_scan_info_t tx_scan_info_in
   , const std::span<size_t> &outs
   , const cryptonote::account_keys keys
   )
  {
    THROW_WALLET_EXCEPTION_IF(i >= tx.vout.size(), tools::error::wallet_internal_error, "Invalid vout index");

    type::tx::tx_scan_info_t tx_scan_info = tx_scan_info_in;

    {
      const auto r = cryptonote::derive_public_key_image_helper_precomp
        (
         keys
        , boost::get<cryptonote::txout_to_key>(tx.vout[i].target).shared_secret_derived_public_key
        , tx_scan_info.received->tx_shared_secret
        , i
        , tx_scan_info.received->index
        );

      THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, "Failed to generate key image");
      std::tie(tx_scan_info.shared_secret_derived_key, tx_scan_info.ki) = *r;

      THROW_WALLET_EXCEPTION_IF
        (
        tx_scan_info.shared_secret_derived_key.pub
        != boost::get<cryptonote::txout_to_key>(tx.vout[i].target).shared_secret_derived_public_key
        , tools::error::wallet_internal_error
        , "shared_secret_derived_public_key_image generated shared secret derived public key not matched with output_key"
        );
    }

    THROW_WALLET_EXCEPTION_IF
      (
      std::find(outs.begin(), outs.end(), i) != outs.end()
      , tools::error::wallet_internal_error
      , "Same output cannot be added twice"
      );

    if (tx_scan_info.money_transfered == 0 && !miner_tx)
    {
      const auto r = decodeRct(tx.ringct_essential, tx_scan_info.received->tx_shared_secret, i);
      if (!r) {
        tx_scan_info.error = true;
        return tx_scan_info;
      }
      std::tie(tx_scan_info.money_transfered, tx_scan_info.mask) = *r;
    }

    if (tx_scan_info.money_transfered == 0)
    {
      LOG_ERROR("Invalid output amount, skipping");
      tx_scan_info.error = true;
      return tx_scan_info;
    }
    tx_scan_info.amount = tx_scan_info.money_transfered;

    return tx_scan_info;
  }

//----------------------------------------------------------------------------------------------------
bool is_spent(const transfer_details &td, bool strict)
{
  if (strict)
  {
    return td.m_spent && td.m_spent_height > 0;
  }
  else
  {
    return td.m_spent;
  }
}

//----------------------------------------------------------------------------------------------------
bool is_transfer_unlocked(const transfer_details& td, const uint64_t current_height)
{
  return is_transfer_unlocked(td.m_tx.unlock_time, td.m_block_height, current_height);
}
//----------------------------------------------------------------------------------------------------
bool is_transfer_unlocked
(
 const uint64_t unlock_time
 , const uint64_t block_height
 , const uint64_t current_height
 )
{
  if(!is_tx_spendtime_unlocked(unlock_time, current_height))
    return false;

  if(block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE > current_height)
    return false;

  return true;
}
//----------------------------------------------------------------------------------------------------
bool is_tx_spendtime_unlocked(const uint64_t unlock_time, const uint64_t current_height)
{
  if (unlock_time == 0) return true;
  return current_height + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS > unlock_time;
}

std::vector<size_t> pick_preferred_rct_inputs
(
 const uint64_t needed_money
 , const uint32_t subaddr_account
 , const std::set<uint32_t> &subaddr_indices
 , const uint64_t current_height
 , const type::wallet::transfer_container_span m_transfers
 )
{
  std::vector<size_t> picks;
  float current_output_relatdness = 1.0f;

  using namespace cryptonote;

  LOG_PRINT_L2("pick_preferred_rct_inputs: needed_money " << print_money(needed_money));

  // try to find a rct input of enough size
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details& td = m_transfers[i];
    if
      (
       !is_spent(td, false)
       && !td.m_frozen
       && td.is_rct()
       && td.amount() >= needed_money
       && is_transfer_unlocked(td, current_height)
       && td.m_subaddr_index.major == subaddr_account
       && subaddr_indices.count(td.m_subaddr_index.minor) == 1
       )
    {
      LOG_PRINT_L2("We can use " << i << " alone: " << print_money(td.amount()));
      picks.push_back(i);
      return picks;
    }
  }

  // then try to find two outputs
  // this could be made better by picking one of the outputs to be a small one, since those
  // are less useful since often below the needed money, so if one can be used in a pair,
  // it gets rid of it for the future
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details& td = m_transfers[i];
    if
      (
       !is_spent(td, false)
       && !td.m_frozen
       && !td.m_shared_secret_derived_public_key_image_partial
       && td.is_rct()
       && is_transfer_unlocked(td, current_height)
       && td.m_subaddr_index.major == subaddr_account
       && subaddr_indices.count(td.m_subaddr_index.minor) == 1
       )
    {
      LOG_PRINT_L2("Considering input " << i << ", " << print_money(td.amount()));
      for (size_t j = i + 1; j < m_transfers.size(); ++j)
      {
        const transfer_details& td2 = m_transfers[j];
        if
          (
           !is_spent(td2, false)
           && !td2.m_frozen
           && !td2.m_shared_secret_derived_public_key_image_partial
           && td2.is_rct()
           && td.amount() + td2.amount() >= needed_money
           && is_transfer_unlocked(td2, current_height)
           && td2.m_subaddr_index == td.m_subaddr_index
           )
        {
          // update our picks if those outputs are less related than any we
          // already found. If the same, don't update, and oldest suitable outputs
          // will be used in preference.
          const float relatedness = get_output_relatedness(td, td2);

          LOG_PRINT_L2
            (
             "  with input "
             <<
             j
             << ", "
             << print_money(td2.amount())
             << ", relatedness "
             << relatedness
             );

          if (relatedness < current_output_relatdness)
          {
            // reset the current picks with those, and return them directly
            // if they're unrelated. If they are related, we'll end up returning
            // them if we find nothing better
            picks.clear();
            picks.push_back(i);
            picks.push_back(j);
            LOG_PRINT_L0("we could use " << i << " and " << j);
            if (relatedness == 0.0f)
              return picks;
            current_output_relatdness = relatedness;
          }
        }
      }
    }
  }

  return picks;
}
} // wallet
} // functional
} // logic
} // wallet
