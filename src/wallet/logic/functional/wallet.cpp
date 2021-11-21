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

#include "wallet/logic/functional/helper.hpp"
#include "wallet/logic/functional/fee.hpp"
#include "wallet/logic/controller/wallet.hpp"

#include "cryptonote/basic/functional/subaddress.hpp"
#include "cryptonote/basic/functional/tx_extra.hpp"

#include "tools/common/apply_permutation.h"
#include "math/ringct/pseudo_functional/ringCT.hpp"
#include "cryptonote/basic/controller/format_utils.hpp"

#include "wallet/api/wallet_errors.h"


#include <boost/exception/to_string.hpp>

namespace wallet {
namespace logic {
namespace functional {
namespace wallet {

  size_t get_num_outputs
  (
   const std::vector<cryptonote::tx_destination_entry> &dsts
   , const type::wallet::transfer_container_span transfers
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
    return get_weight_string(blob_size);
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

  std::pair<std::set<uint64_t>, size_t> outs_unique(const std::vector<std::vector<::wallet::logic::type::get_tx_outputs_entry>> outs)
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
  type::tx::tx_scan_info_t scan_output_for_subaddresses
  (
   const cryptonote::tx_out o
   , const crypto::ecdh_shared_secret tx_output_shared_secret
   , const size_t i
   , const serializable_unordered_map<crypto::public_key, cryptonote::subaddress_index>& m_subaddresses
   )
  {

    if (o.target.type() !=  typeid(cryptonote::txout_to_key))
    {
      LOG_ERROR("wrong type id in transaction out");
      return type::tx::tx_scan_info_t();
    }

    // const auto secret
    //   = tx_output_shared_secrets.contains(i)
    //   ? tx_output_shared_secrets.at(i)
    //   : std::optional<crypto::ecdh_shared_secret>();

    const auto received = check_output_for_subaddresses
      (
       m_subaddresses
       , boost::get<cryptonote::txout_to_key>(o.target).output_public_key
       , tx_output_shared_secret
       , i
       );

    const auto money_transfered
      = received
      ? o.amount
      : 0;

    return type::tx::tx_scan_info_t(money_transfered, received);
  }

  //----------------------------------------------------------------------------------------------------
  std::optional<std::pair<uint64_t, rct::rct_scalar>> decodeRct
  (
   const rct::rctData rv
   , const crypto::ecdh_shared_secret tx_output_shared_secret
   , const unsigned int i
   )
  {
    const crypto::ec_scalar hashed_secret = crypto::hash_tx_output_shared_secret_to_scalar(tx_output_shared_secret, i);
    try
    {
      switch (rv.type)
        {
        case rct::RCTTypeCLSAG: {
          return {rct::decode_ringct_commitment(rv, hashed_secret, i)};
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
      const auto r = cryptonote::derive_output_key_pair_and_key_image
        (
         keys
        , boost::get<cryptonote::txout_to_key>(tx.vout[i].target).output_public_key
        , tx_scan_info.received->tx_output_shared_secret
        , i
        , tx_scan_info.received->index
        );

      THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, "Failed to generate key image");
      std::tie(tx_scan_info.output_spend_key, tx_scan_info.ki) = *r;

      THROW_WALLET_EXCEPTION_IF
        (
        tx_scan_info.output_spend_key.pub
        != boost::get<cryptonote::txout_to_key>(tx.vout[i].target).output_public_key
        , tools::error::wallet_internal_error
        , "shared secret derived spend public key does not matched with output spend public key"
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
      const auto r = decodeRct(tx.ringct, tx_scan_info.received->tx_output_shared_secret, i);
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
       && !td.m_output_key_image_partial
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
           && !td2.m_output_key_image_partial
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

std::pair<type::tx::pending_tx, cryptonote::transaction> transfer_selected_rct
(
 const std::vector<cryptonote::tx_destination_entry> dsts
 , const std::vector<size_t> selected_transfers
 , const size_t fake_outputs_count
 , const std::span<const std::vector<type::get_tx_outputs_entry>> outs
 , const uint64_t unlock_time
 , const uint64_t fee
 , const std::vector<uint8_t> extra
 , const type::wallet::transfer_container_span m_transfers
 , const cryptonote::account_keys account_keys
 , const serializable_unordered_map<crypto::public_key, cryptonote::subaddress_index>& m_subaddresses
 , const cryptonote::network_type m_nettype
 )
{
  using namespace cryptonote;

  type::tx::pending_tx ptx;
  cryptonote::transaction tx;

  // throw if attempting a transaction with no destinations
  THROW_WALLET_EXCEPTION_IF(dsts.empty(), tools::error::zero_destination);

  constexpr uint64_t upper_transaction_weight_limit =
    get_upper_transaction_weight_limit();

  uint64_t needed_money = fee;
  LOG_PRINT_L2("transfer_selected_rct: starting with fee " << print_money (needed_money));
  LOG_PRINT_L2("selected transfers: " << helper::strjoin(selected_transfers, " "));

  // calculate total amount being sent to all destinations
  // throw if total amount overflows uint64_t
  for(auto& dt: dsts)
  {
    THROW_WALLET_EXCEPTION_IF(0 == dt.amount, tools::error::zero_destination);
    needed_money += dt.amount;
    LOG_PRINT_L2("transfer: adding " << print_money(dt.amount) << ", for a total of " << print_money (needed_money));
    THROW_WALLET_EXCEPTION_IF(needed_money < dt.amount, tools::error::tx_sum_overflow, dsts, fee, m_nettype);
  }

  std::vector<std::unordered_set<crypto::public_key>> ignore_sets;

  uint64_t found_money = 0;
  for(size_t idx: selected_transfers)
  {
    found_money += m_transfers[idx].amount();
  }

  LOG_PRINT_L2("wanted " << print_money(needed_money) << ", found " << print_money(found_money) << ", fee " << print_money(fee));
  THROW_WALLET_EXCEPTION_IF(found_money < needed_money, tools::error::not_enough_unlocked_money, found_money, needed_money - fee, fee);

  uint32_t subaddr_account = m_transfers[*selected_transfers.begin()].m_subaddr_index.major;
  for (auto i = ++selected_transfers.begin(); i != selected_transfers.end(); ++i)
    THROW_WALLET_EXCEPTION_IF(subaddr_account != m_transfers[*i].m_subaddr_index.major, tools::error::wallet_internal_error, "the tx uses funds from multiple accounts");

  //prepare inputs
  LOG_PRINT_L2("preparing outputs");
  size_t i = 0, out_index = 0;
  std::vector<cryptonote::tx_source_entry> sources;
  std::unordered_set<rct::rct_point> used_L;
  for(size_t idx: selected_transfers)
  {
    sources.resize(sources.size()+1);
    cryptonote::tx_source_entry& src = sources.back();
    const transfer_details& td = m_transfers[idx];
    src.amount = td.amount();
    src.rct = td.is_rct();
    //paste mixin transaction

    THROW_WALLET_EXCEPTION_IF(outs.size() < out_index + 1 ,  tools::error::wallet_internal_error, "outs.size() < out_index + 1");
    THROW_WALLET_EXCEPTION_IF(outs[out_index].size() < fake_outputs_count ,  tools::error::wallet_internal_error, "fake_outputs_count > random outputs found");

    typedef cryptonote::tx_source_entry::output_entry tx_output_entry;
    for (size_t n = 0; n < fake_outputs_count + 1; ++n)
    {
      tx_output_entry oe;
      oe.first = std::get<0>(outs[out_index][n]);
      oe.second.output_public_key = std::get<1>(outs[out_index][n]);
      oe.second.commit = std::get<2>(outs[out_index][n]);
      src.outputs.push_back(oe);
    }
    ++i;

    //paste real transaction to the random index
    auto it_to_replace = std::find_if(src.outputs.begin(), src.outputs.end(), [&](const tx_output_entry& a)
    {
      return a.first == td.m_global_output_index;
    });
    THROW_WALLET_EXCEPTION_IF(it_to_replace == src.outputs.end(), tools::error::wallet_internal_error,
        "real output not found");

    tx_output_entry real_oe;
    real_oe.first = td.m_global_output_index;
    real_oe.second.output_public_key = td.get_public_key();
    real_oe.second.commit = rct::commit(td.amount(), td.m_mask);
    *it_to_replace = real_oe;
    src.real_out_tx_key = get_tx_pub_key_from_extra(td.m_tx).value_or(crypto::null_pkey);
    const std::vector<crypto::public_key> no_keys;
    src.real_out_output_secret_keys =
      get_tx_output_public_keys_from_extra(td.m_tx).value_or(no_keys);
    src.real_output = it_to_replace - src.outputs.begin();
    src.real_output_in_tx_index = td.m_internal_output_index;
    src.mask = td.m_mask;
    controller::wallet::print_source_entry(src);
    ++out_index;
  }
  LOG_PRINT_L2("outputs prepared");

  // we still keep a copy, since we want to keep dsts free of change for user feedback purposes
  std::vector<cryptonote::tx_destination_entry> splitted_dsts = dsts;

  cryptonote::tx_destination_entry change_dts = AUTO_VAL_INIT(change_dts);
  change_dts.amount = found_money - needed_money;
  if (change_dts.amount != 0)
  {
    const uint32_t change_subaddress_index = subaddr_account == 0 ? 1 : 0;
    change_dts.addr =
      cryptonote::get_subaddress
      (
       account_keys.get_spend_view_secret_keys()
       , {subaddr_account, change_subaddress_index}
       );
    change_dts.is_subaddress = true;
    splitted_dsts.push_back(change_dts);
  }

  LOG_PRINT_L2("constructing tx");
  auto sources_copy = sources;
  const auto r = cryptonote::construct_tx_and_get_tx_key
    (
     account_keys
     , m_subaddresses
     , sources
     , splitted_dsts
     , extra
     , unlock_time
     );
  THROW_WALLET_EXCEPTION_IF(!r, tools::error::tx_not_constructed, sources, dsts, unlock_time, m_nettype);

  const auto [tx_out, permutation, output_secret_keys] = *r;

  tx = tx_out;

  LOG_PRINT_L2("constructed tx");

  THROW_WALLET_EXCEPTION_IF(upper_transaction_weight_limit <= get_transaction_weight(tx), tools::error::tx_too_big, tx, upper_transaction_weight_limit);

  LOG_PRINT_L2("gathering key images");
  std::string output_key_images;
  bool all_are_txin_to_key = std::all_of(tx.vin.begin(), tx.vin.end(), [&](const txin_v& s_e) -> bool
  {
    CHECKED_GET_SPECIFIC_VARIANT(s_e, const txin_to_key, in, false);
    output_key_images += boost::to_string(in.output_key_image) + " ";
    return true;
  });
  THROW_WALLET_EXCEPTION_IF(!all_are_txin_to_key, tools::error::unexpected_txin_type, tx);
  LOG_PRINT_L2("gathered key images");

  ptx.output_key_images = output_key_images;
  ptx.fee = fee;
  ptx.dust = 0;
  ptx.dust_added_to_fee = false;
  ptx.tx = tx;
  ptx.change_dts = change_dts;
  ptx.selected_transfers = selected_transfers;
  ptx.output_secret_keys = output_secret_keys;
  ptx.dests = dsts;
  ptx.construction_data.sources = sources_copy;
  ptx.construction_data.change_dts = change_dts;
  ptx.construction_data.splitted_dsts = splitted_dsts;
  ptx.construction_data.selected_transfers = ptx.selected_transfers;
  ptx.selected_transfers = tools::apply_permutation(permutation, ptx.selected_transfers);
  ptx.construction_data.extra = tx.extra;
  ptx.construction_data.unlock_time = unlock_time;
  ptx.construction_data.use_rct = true;
  ptx.construction_data.dests = dsts;
  // record which subaddress indices are being used as inputs
  ptx.construction_data.subaddr_account = subaddr_account;
  ptx.construction_data.subaddr_indices.clear();
  for (size_t idx: selected_transfers)
    ptx.construction_data.subaddr_indices.insert(m_transfers[idx].m_subaddr_index.minor);
  LOG_PRINT_L2("transfer_selected_rct done");

  return {ptx, tx};
}

std::map<uint32_t, uint64_t> balance_per_subaddress
(
 const uint32_t subaddr_index_major
 , const bool only_confirmed
 , const type::wallet::transfer_container_span m_transfers
 , const serializable_unordered_map<crypto::hash, type::transfer::unconfirmed_transfer_details> m_unconfirmed_txs
 )
{
  std::map<uint32_t, uint64_t> amount_per_subaddr;
  for (const auto& td: m_transfers)
  {
    if
      (
       td.m_subaddr_index.major == subaddr_index_major
       && !is_spent(td, only_confirmed)
       && !td.m_frozen
       )
    {
      auto found = amount_per_subaddr.find(td.m_subaddr_index.minor);
      if (found == amount_per_subaddr.end())
        amount_per_subaddr[td.m_subaddr_index.minor] = td.amount();
      else
        found->second += td.amount();
    }
  }
  if (!only_confirmed)
  {
   for (const auto& utx: m_unconfirmed_txs)
   {
    if (utx.second.m_subaddr_account == subaddr_index_major && utx.second.m_state != type::transfer::unconfirmed_transfer_details::failed)
    {
      // all changes go to 0-th subaddress (in the current subaddress account)
      auto found = amount_per_subaddr.find(0);
      if (found == amount_per_subaddr.end())
        amount_per_subaddr[0] = utx.second.m_change;
      else
        found->second += utx.second.m_change;
    }
   }
  }
  return amount_per_subaddr;
}

//----------------------------------------------------------------------------------------------------
std::map<uint32_t, std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> unlocked_balance_per_subaddress
(
 const uint32_t subaddr_index_major
 , const bool only_confirmed
 , const type::wallet::transfer_container_span m_transfers
 , const uint64_t blockchain_height
 )
{
  std::map<uint32_t, std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> amount_per_subaddr;
  for(const transfer_details& td: m_transfers)
  {
    if(td.m_subaddr_index.major == subaddr_index_major && !is_spent(td, only_confirmed) && !td.m_frozen)
    {
      uint64_t amount = 0, blocks_to_unlock = 0, time_to_unlock = 0;
      if (is_transfer_unlocked(td, blockchain_height))
      {
        amount = td.amount();
        blocks_to_unlock = 0;
        time_to_unlock = 0;
      }
      else
      {
        uint64_t unlock_height = td.m_block_height + std::max<uint64_t>(CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE, CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS);
        if (td.m_tx.unlock_time > unlock_height)
          unlock_height = td.m_tx.unlock_time;
        blocks_to_unlock = unlock_height > blockchain_height ? unlock_height - blockchain_height : 0;
        time_to_unlock = 0;
        amount = 0;
      }
      auto found = amount_per_subaddr.find(td.m_subaddr_index.minor);
      if (found == amount_per_subaddr.end())
        amount_per_subaddr[td.m_subaddr_index.minor] = std::make_pair(amount, std::make_pair(blocks_to_unlock, time_to_unlock));
      else
      {
        found->second.first += amount;
        found->second.second.first = std::max(found->second.second.first, blocks_to_unlock);
        found->second.second.second = std::max(found->second.second.second, time_to_unlock);
      }
    }
  }
  return amount_per_subaddr;
}

uint64_t calculate_fee
(
 const cryptonote::transaction tx
 , const size_t blob_size
 , const uint64_t base_fee
 , const uint64_t fee_multiplier
 , const uint64_t fee_quantization_mask
 )
{
  return fee::calculate_fee_from_weight
    (base_fee, blob_size, fee_multiplier, fee_quantization_mask);
}


unconfirmed_transfer_details get_unconfirmed_transfer_details
(
 const cryptonote::transaction& tx
 , const uint64_t amount_in
 , const std::vector<cryptonote::tx_destination_entry> &dests
 , const uint64_t change_amount
 , const uint32_t subaddr_account
 , const std::set<uint32_t>& subaddr_indices
 )
{
  unconfirmed_transfer_details utd;
  utd.m_amount_in = amount_in;
  utd.m_amount_out = 0;
  for (const auto &d: dests)
    utd.m_amount_out += d.amount;
  utd.m_amount_out += change_amount; // dests does not contain change
  utd.m_change = change_amount;
  utd.m_sent_time = time(NULL);
  utd.m_tx = (const cryptonote::transaction_prefix&)tx;
  utd.m_dests = dests;
  utd.m_state = type::transfer::unconfirmed_transfer_details::pending;
  utd.m_timestamp = time(NULL);
  utd.m_subaddr_account = subaddr_account;
  utd.m_subaddr_indices = subaddr_indices;
  for (const auto &in: tx.vin)
  {
    if (in.type() != typeid(cryptonote::txin_to_key))
      continue;
    const auto &txin = boost::get<cryptonote::txin_to_key>(in);
    utd.m_rings.push_back(std::make_pair(txin.output_key_image, txin.output_relative_offsets));
  }

  return utd;
}

} // wallet
} // functional
} // logic
} // wallet
