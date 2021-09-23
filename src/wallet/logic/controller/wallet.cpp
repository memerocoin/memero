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

#include "wallet/logic/type/wallet.hpp"
#include "wallet/logic/type/transfer.hpp"
#include "wallet/logic/functional/wallet.hpp"
#include "wallet/logic/functional/helper.hpp"
#include "wallet/logic/functional/fee.hpp"
#include "wallet/logic/pseudo_functional/proof.hpp"
#include "wallet/logic/controller/proof.hpp"

#include "wallet/api/wallet_errors.h"

#include "cryptonote/basic/functional/subaddress.hpp"
#include "cryptonote/tx/tx_sanity_check.h"

#include "wallet/api/wallet_errors.h"

#include <rapidjson/document.h>
#include <rapidjson/writer.h>

#include "tools/epee/include/string_tools.h"
#include "tools/epee/include/file_io_utils.h"
#include "tools/epee/include/storages/portable_storage_template_helper.h"
#include "tools/serialization/binary_utils.h"
#include "tools/common/json_util.h"

#include "math/crypto/controller/random.hpp"

#include <cstdint>

//----------------------------------------------------------------------------------------------------
namespace
{
  template<typename T>
  T pop_back(std::vector<T>& vec)
  {
    LOG_ERROR_AND_RETURN_UNLESS(!vec.empty(), T(), "Vector must be non-empty");

    T res = vec.back();
    vec.pop_back();
    return res;
  }

  template<typename T>
  void pop_if_present(std::vector<T>& vec, T e)
  {
    for (size_t i = 0; i < vec.size(); ++i)
      {
        if (e == vec[i])
          {
            pop_index (vec, i);
            return;
          }
      }
  }

  constexpr uint64_t TX_WEIGHT_TARGET(const uint64_t bytes) {
    return bytes * 2 / 3;
  }

}


namespace wallet {
namespace logic {
namespace controller {
namespace wallet {

  void do_prepare_file_names
  (
   const std::string& file_path
   , std::string& keys_file
   , std::string& wallet_file
   )
  {
    std::error_code e;
    if(std::filesystem::path(file_path).extension() == ".keys")
    {
      //provided keys file name
      keys_file = file_path;
      wallet_file = std::filesystem::path(file_path).replace_extension("");
    } else
    {
      //provided wallet file name
      keys_file = file_path + ".keys";
      wallet_file = file_path;
    }
  }


  bool save_to_file
  (
   const std::string& path_to_file
   , const std::string& raw
   )
  {
    return epee::file_io_utils::save_string_to_file(path_to_file, raw);
  }

  bool load_from_file
  (
   const std::string& path_to_file
   , std::string& target_str
   , const size_t max_size
   )
  {
    return epee::file_io_utils::load_file_to_string(path_to_file, target_str, max_size);
  }

  void print_source_entry(const cryptonote::tx_source_entry& src)
  {
    std::string indexes;
    std::for_each
      (src.outputs.begin(), src.outputs.end(),
       [&](const cryptonote::tx_source_entry::output_entry& s_e) {
         indexes += std::to_string(s_e.first) + " ";
       }
       );
    LOG_PRINT_L0("amount=" << cryptonote::print_money(src.amount)
                 << ", real_output=" <<src.real_output
                 << ", real_output_in_tx_index=" << src.real_output_in_tx_index
                 << ", indexes: " << indexes);
  }

  /*!
  * \brief verify password for specified wallet keys file.
  * \param keys_file_name  Keys file to verify password for
  * \param password        Password to verify
  * \param no_spend_key    If set = only verify view keys, otherwise also spend keys
  * \param hwdev           The hardware device to use
  * \return                true if password is correct
  *
  * for verification only
  * should not mutate state, unlike load_keys()
  * can be used prior to rewriting wallet keys file, to ensure user has entered the correct password
  *
  */
  bool verify_password(const std::string& keys_file_name, const epee::wipeable_string& password, bool no_spend_key, uint64_t kdf_rounds)
  {
    rapidjson::Document json;
    ::wallet::logic::type::wallet::keys_file_data keys_file_data;
    std::string buf;
    bool encrypted_secret_keys = false;
    bool r = ::wallet::logic::controller::wallet::load_from_file(keys_file_name, buf);
    THROW_WALLET_EXCEPTION_IF(!r, tools::error::file_read_error, keys_file_name);

    // Decrypt the contents
    r = ::serialization::parse_binary(buf, keys_file_data);
    THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, "internal error: failed to deserialize \"" + keys_file_name + '\"');
    crypto::chacha_key key;
    crypto::generate_chacha_key(password.data(), password.size(), key, kdf_rounds);
    std::string account_data;
    account_data.resize(keys_file_data.account_data.size());
    crypto::chacha20(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);
    json.Parse(account_data.c_str());

    {
      account_data = std::string(json["key_data"].GetString(), json["key_data"].GetString() +
        json["key_data"].GetStringLength());
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, encrypted_secret_keys, uint32_t, Uint, false, false);
      encrypted_secret_keys = field_encrypted_secret_keys;
    }

    cryptonote::account_base account_data_check;

    r = epee::serialization::load_t_from_binary(account_data_check, account_data);

    if (encrypted_secret_keys)
      account_data_check.decrypt_keys(key);

    const cryptonote::account_keys& keys = account_data_check.get_keys();
    r = r && crypto::verify_keys(keys.m_view_secret_key,  keys.m_account_address.m_view_public_key);
    if(!no_spend_key)
      r = r && crypto::verify_keys(keys.m_spend_secret_key, keys.m_account_address.m_spend_public_key);
    return r;
  }

  //----------------------------------------------------------------------------------------------------
  size_t pop_best_value_from
  (
    const ::wallet::logic::type::wallet::transfer_container_span transfers
    , std::vector<size_t> &unused_indices
    , const std::span<size_t> selected_transfers
    , bool smallest
    )
  {
    std::vector<size_t> candidates;
    float best_relatedness = 1.0f;
    for (size_t n = 0; n < unused_indices.size(); ++n)
    {
      const ::wallet::logic::type::transfer::transfer_details &candidate = transfers[unused_indices[n]];
      float relatedness = 0.0f;
      for (const auto &i: selected_transfers)
      {
        float r = ::wallet::logic::functional::wallet::get_output_relatedness(candidate, transfers[i]);
        if (r > relatedness)
        {
          relatedness = r;
          if (relatedness == 1.0f)
            break;
        }
      }

      if (relatedness < best_relatedness)
      {
        best_relatedness = relatedness;
        candidates.clear();
      }

      if (relatedness == best_relatedness)
        candidates.push_back(n);
    }

    // we have all the least related outputs in candidates, so we can pick either
    // the smallest, or a random one, depending on request
    size_t idx;
    if (smallest)
    {
      idx = 0;
      for (size_t n = 0; n < candidates.size(); ++n)
      {
        const transfer_details &td = transfers[unused_indices[candidates[n]]];
        if (td.amount() < transfers[unused_indices[candidates[idx]]].amount())
          idx = n;
      }
    }
    else
    {
      idx = crypto::rand_idx(candidates.size());
    }
    return pop_index (unused_indices, candidates[idx]);
  }


  std::vector<std::vector<type::get_tx_outputs_entry>> get_tx_outputs
  (
  const std::vector<size_t> selected_transfers
  , const size_t fake_outputs_count
  , const tools::RPC_Client m_rpc_client
  , const type::wallet::transfer_container_span m_transfers
  )
  {
    std::vector<std::vector<type::get_tx_outputs_entry>> outs;
    std::vector<uint64_t> rct_offsets;

    for (size_t attempts = config::lol::get_out_retry; attempts > 0; --attempts)
    {
      m_rpc_client.get_tx_outputs(selected_transfers, m_transfers, fake_outputs_count, outs, rct_offsets);

      const auto unique = functional::wallet::outs_unique(outs);
      if (cryptonote::tx_sanity_check(unique.first, unique.second, rct_offsets.empty() ? 0 : rct_offsets.back()))
      {
        return outs;
      }

      std::vector<crypto::shared_secret_derived_public_key_image> shared_secret_derived_public_key_images;
      shared_secret_derived_public_key_images.reserve(selected_transfers.size());
      std::for_each
        (
         selected_transfers.begin()
         , selected_transfers.end()
         , [m_transfers, &shared_secret_derived_public_key_images](size_t index) {
           shared_secret_derived_public_key_images.push_back(m_transfers[index].m_shared_secret_derived_public_key_image);
         }
         );
    }

    THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, "Transaction sanity check failed");

    return {};
  }

   std::pair<type::tx::pending_tx, cryptonote::transaction> transfer_selected_rct
   (
    std::vector<std::vector<type::get_tx_outputs_entry>> &outs
    , const tools::RPC_Client m_rpc_client
    , const std::vector<cryptonote::tx_destination_entry> dsts
    , const std::vector<size_t> selected_transfers
    , const size_t fake_outputs_count
    , const uint64_t unlock_time
    , const uint64_t fee
    , const std::vector<uint8_t> extra
    , const type::wallet::transfer_container_span m_transfers
    , const cryptonote::account_keys account_keys
    , const serializable_unordered_map<crypto::public_key, cryptonote::subaddress_index>& m_subaddresses
    , const cryptonote::network_type m_nettype
   ) {
    if (outs.empty()) {
      outs = get_tx_outputs(selected_transfers, fake_outputs_count, m_rpc_client, m_transfers); // may throw
    }

    return functional::wallet::transfer_selected_rct
      (
       dsts
       , selected_transfers
       , fake_outputs_count
       , outs
       , unlock_time
       , fee
       , extra
       , m_transfers
       , account_keys
       , m_subaddresses
       , m_nettype
       );
  }


  bool sanity_check
  (
  const std::span<const type::tx::pending_tx> ptx_vector
  , const std::span<const cryptonote::tx_destination_entry> dsts
  , const type::wallet::transfer_container_span m_transfers
  , const serializable_unordered_map<crypto::public_key, cryptonote::subaddress_index>& m_subaddresses
  , const crypto::secret_key m_view_secret_key
  , const cryptonote::network_type m_nettype
  )
  {
    using namespace cryptonote;

    LOG_DEBUG("sanity_check: " << ptx_vector.size() << " txes, " << dsts.size() << " destinations");

    THROW_WALLET_EXCEPTION_IF(ptx_vector.empty(), tools::error::wallet_internal_error, "No transactions");

    // check every party in there does receive at least the required amount
    std::unordered_map<account_public_address, std::pair<uint64_t, bool>> required;
    for (const auto &d: dsts)
    {
      required[d.addr].first += d.amount;
      required[d.addr].second = d.is_subaddress;
    }

    // add change
    uint64_t change = 0;
    for (const auto &ptx: ptx_vector)
    {
      for (size_t idx: ptx.selected_transfers)
        change += m_transfers[idx].amount();
      change -= ptx.fee;
    }
    for (const auto &r: required)
      change -= r.second.first;

    LOG_DEBUG("Adding " << cryptonote::print_money(change) << " expected change");

    // for all txes that have actual change, check change is coming back to the sending wallet
    for (const type::tx::pending_tx &ptx: ptx_vector)
    {
      if (ptx.change_dts.amount == 0)
        continue;
      THROW_WALLET_EXCEPTION_IF
        (
         m_subaddresses.find(ptx.change_dts.addr.m_spend_public_key) == m_subaddresses.end()
         , tools::error::wallet_internal_error
         , "Change address is not ours"
         );
      required[ptx.change_dts.addr].first += ptx.change_dts.amount;
      required[ptx.change_dts.addr].second = ptx.change_dts.is_subaddress;
    }

    for (const auto &r: required)
    {
      const account_public_address address = r.first;
      const bool is_subaddress = r.second.second;

      bool found_in_some_tx = false;

      for (const auto &ptx: ptx_vector)
      {
        std::string proof = controller::proof::get_tx_output_signatures
          (
           ptx.output_secret_keys
           , address
           , is_subaddress
           , "automatic-sanity-check"
           );

        const auto found_indices = pseudo_functional::proof::verify_tx_output_signatures
          (ptx.tx, address, r.second.second, "automatic-sanity-check", proof);

        if (found_indices) {
          found_in_some_tx = true;
          break;
        }
      }
      THROW_WALLET_EXCEPTION_IF
        (
         !found_in_some_tx
         , tools::error::wallet_internal_error
         , "invalid tx proof in auto sanity check"
         );
    }

    return true;
  }

  struct TX {
    std::vector<size_t> selected_transfers;
    std::vector<cryptonote::tx_destination_entry> dsts;
    cryptonote::transaction tx;
    type::tx::pending_tx ptx;
    size_t weight;
    uint64_t needed_fee;
    std::vector<std::vector<type::get_tx_outputs_entry>> outs;

    TX() : weight(0), needed_fee(0) {}

    void add(const cryptonote::tx_destination_entry &de, uint64_t amount, unsigned int original_output_index, bool merge_destinations) {
      if (merge_destinations)
      {
        std::vector<cryptonote::tx_destination_entry>::iterator i;
        i = std::find_if
          (
           dsts.begin()
           , dsts.end()
           , [&](const cryptonote::tx_destination_entry &d) {
             return !memcmp (&d.addr, &de.addr, sizeof(de.addr));
           }
           );

        if (i == dsts.end())
        {
          dsts.push_back(de);
          i = dsts.end() - 1;
          i->amount = 0;
        }
        i->amount += amount;
      }
      else
      {
        THROW_WALLET_EXCEPTION_IF
          (
           original_output_index > dsts.size()
           , tools::error::wallet_internal_error
           , std::string("original_output_index too large: ")
           + std::to_string(original_output_index) + " > " + std::to_string(dsts.size())
           );

        if (original_output_index == dsts.size())
        {
          dsts.push_back(de);
          dsts.back().amount = 0;
        }

        THROW_WALLET_EXCEPTION_IF
          (
           memcmp(&dsts[original_output_index].addr, &de.addr, sizeof(de.addr))
           , tools::error::wallet_internal_error
           , "Mismatched destination address"
           );

        dsts[original_output_index].amount += amount;
      }
    }
  };

  // Another implementation of transaction creation that is hopefully better
  // While there is anything left to pay, it goes through random outputs and tries
  // to fill the next destination/amount. If it fully fills it, it will use the
  // remainder to try to fill the next one as well.
  // The tx size if roughly estimated as a linear function of only inputs, and a
  // new tx will be created when that size goes above a given fraction of the
  // max tx size. At that point, more outputs may be added if the fee cannot be
  // satisfied.
  // If the next output in the next tx would go to the same destination (ie, we
  // cut off at a tx boundary in the middle of paying a given destination), the
  // fee will be carved out of the current input if possible, to avoid having to
  // add another output just for the fee and getting change.
  // This system allows for sending (almost) the entire balance, since it does
  // not generate spurious change in all txes, thus decreasing the instantaneous
  // usable balance.
  std::vector<type::tx::pending_tx> create_transactions
  (
  const std::vector<cryptonote::tx_destination_entry> dsts_vec
  , const size_t fake_outs_count
  , const uint64_t unlock_time
  , const uint32_t priority
  , const std::vector<uint8_t> extra
  , const uint32_t subaddr_account
  , const std::set<uint32_t> subaddr_indices_
  , const cryptonote::network_type m_nettype
  , const type::wallet::transfer_container_span m_transfers
  , const serializable_unordered_map<crypto::hash, type::transfer::unconfirmed_transfer_details> m_unconfirmed_txs
  , const uint64_t blockchain_height
  , const bool m_ignore_fractional_outputs
  , const bool m_merge_destinations
  , const tools::RPC_Client m_rpc_client
  , const cryptonote::account_keys account_keys
  , const serializable_unordered_map<crypto::public_key, cryptonote::subaddress_index>& m_subaddresses
  , const uint64_t unlocked_balance
  )
  {
    using namespace tools;
    using namespace type::tx;
    using namespace functional::fee;
    using namespace cryptonote;

    auto dsts = dsts_vec;

    auto subaddr_indices = subaddr_indices_;

    //ensure device is let in NONE mode in any case

    const auto original_dsts = dsts;

    std::vector<std::pair<uint32_t, std::vector<size_t>>> unused_transfers_indices_per_subaddr;
    std::vector<std::pair<uint32_t, std::vector<size_t>>> unused_dust_indices_per_subaddr;
    uint64_t needed_money;
    std::vector<TX> txes;
    bool adding_fee; // true if new outputs go towards fee, rather than destinations
    uint64_t needed_fee, available_for_fee = 0;
    constexpr uint64_t upper_transaction_weight_limit =
      functional::wallet::get_upper_transaction_weight_limit();

    const uint64_t base_fee  = get_base_fee();
    const uint64_t fee_multiplier = get_fee_multiplier(priority);
    const uint64_t fee_quantization_mask = constant::fee_quantization_mask;

    // throw if attempting a transaction with no destinations
    THROW_WALLET_EXCEPTION_IF(dsts.empty(), error::zero_destination);

    // calculate total amount being sent to all destinations
    // throw if total amount overflows uint64_t
    needed_money = 0;

    for(auto& dt: dsts)
    {
      THROW_WALLET_EXCEPTION_IF(0 == dt.amount, error::zero_destination);
      needed_money += dt.amount;
      LOG_PRINT_L2("transfer: adding " << print_money(dt.amount) << ", for a total of " << print_money (needed_money));
      THROW_WALLET_EXCEPTION_IF(needed_money < dt.amount, error::tx_sum_overflow, dsts, 0, m_nettype);
    }

    // throw if attempting a transaction with no money
    THROW_WALLET_EXCEPTION_IF(needed_money == 0, error::zero_destination);

    std::map<uint32_t, std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> unlocked_balance_per_subaddr =
      functional::wallet::unlocked_balance_per_subaddress(subaddr_account, false, m_transfers, blockchain_height);
    std::map<uint32_t, uint64_t> balance_per_subaddr =
      functional::wallet::balance_per_subaddress(subaddr_account, false, m_transfers, m_unconfirmed_txs);

    if (subaddr_indices.empty()) // "index=<N1>[,<N2>,...]" wasn't specified -> use all the indices with non-zero unlocked balance
    {
      for (const auto& i : balance_per_subaddr) {
        subaddr_indices.insert(i.first);
      }
    }

    // early out if we know we can't make it anyway
    // we could also check for being within FEE_PER_KB, but if the fee calculation
    // ever changes, this might be missed, so let this go through
    const uint64_t min_fee = (fee_multiplier * base_fee * estimate_tx_size(1, fake_outs_count, 2, extra.size()));
    uint64_t balance_subtotal = 0;
    uint64_t unlocked_balance_subtotal = 0;

    for (uint32_t index_minor : subaddr_indices)
    {
      balance_subtotal += balance_per_subaddr[index_minor];
      unlocked_balance_subtotal += unlocked_balance_per_subaddr[index_minor].first;
    }

    THROW_WALLET_EXCEPTION_IF
      (
       needed_money + min_fee > balance_subtotal
       , error::not_enough_money
       , balance_subtotal
       , needed_money
       , 0
       );

    // first check overall balance is enough, then unlocked one, so we throw distinct exceptions
    THROW_WALLET_EXCEPTION_IF
      (
       needed_money + min_fee > unlocked_balance_subtotal
       , error::not_enough_unlocked_money
       , unlocked_balance_subtotal
       , needed_money
       , 0
       );

    for (uint32_t i : subaddr_indices) {
      LOG_PRINT_L2("Candidate subaddress index for spending: " << i);
    }

    // determine threshold for fractional amount
    const size_t tx_weight_one_ring = estimate_tx_weight(1, fake_outs_count, 2, 0);
    const size_t tx_weight_two_rings = estimate_tx_weight(2, fake_outs_count, 2, 0);
    THROW_WALLET_EXCEPTION_IF
      (
       tx_weight_one_ring > tx_weight_two_rings
       , error::wallet_internal_error
       , "Estimated tx weight with 1 input is larger than with 2 inputs!"
       );

    const size_t tx_weight_per_ring = tx_weight_two_rings - tx_weight_one_ring;
    const uint64_t fractional_threshold = (fee_multiplier * base_fee * tx_weight_per_ring);

    // gather all dust and non-dust outputs belonging to specified subaddresses
    size_t num_nondust_outputs = 0;
    size_t num_dust_outputs = 0;

    const uint64_t current_height = blockchain_height;
    for (size_t i = 0; i < m_transfers.size(); ++i)
    {
      const transfer_details& td = m_transfers[i];
      if (m_ignore_fractional_outputs && td.amount() < fractional_threshold)
      {
        LOG_DEBUG
          (
           "Ignoring output "
           << i
           << " of amount "
           << print_money(td.amount())
           << " which is below fractional threshold "
           << print_money(fractional_threshold)
           );

        continue;
      }

      if
        (
         !functional::wallet::is_spent(td, false)
         && !td.m_frozen
         && !td.m_shared_secret_derived_public_key_image_partial
         && functional::wallet::is_transfer_unlocked(td, current_height)
         && td.m_subaddr_index.major == subaddr_account
         && subaddr_indices.count(td.m_subaddr_index.minor) == 1
         )
        {
          const uint32_t index_minor = td.m_subaddr_index.minor;
          auto find_predicate = [&index_minor](const std::pair<uint32_t, std::vector<size_t>>& x) { return x.first == index_minor; };
          if (td.is_rct())
          {
            auto found = std::find_if(unused_transfers_indices_per_subaddr.begin(), unused_transfers_indices_per_subaddr.end(), find_predicate);
            if (found == unused_transfers_indices_per_subaddr.end())
            {
              unused_transfers_indices_per_subaddr.push_back({index_minor, {i}});
            }
            else
            {
              found->second.push_back(i);
            }
            ++num_nondust_outputs;
          }
          else
          {
            auto found = std::find_if(unused_dust_indices_per_subaddr.begin(), unused_dust_indices_per_subaddr.end(), find_predicate);
            if (found == unused_dust_indices_per_subaddr.end())
            {
              unused_dust_indices_per_subaddr.push_back({index_minor, {i}});
            }
            else
            {
              found->second.push_back(i);
            }
            ++num_dust_outputs;
          }
        }
    }
    
    // sort output indices
    {
      auto sort_predicate = [&unlocked_balance_per_subaddr]
        (const std::pair<uint32_t, std::vector<size_t>>& x, const std::pair<uint32_t, std::vector<size_t>>& y)
      {
        return unlocked_balance_per_subaddr[x.first].first > unlocked_balance_per_subaddr[y.first].first;
      };

      std::sort(unused_transfers_indices_per_subaddr.begin(), unused_transfers_indices_per_subaddr.end(), sort_predicate);
      std::sort(unused_dust_indices_per_subaddr.begin(), unused_dust_indices_per_subaddr.end(), sort_predicate);
    }

    LOG_PRINT_L2("Starting with " << num_nondust_outputs << " non-dust outputs and " << num_dust_outputs << " dust outputs");

    if (unused_dust_indices_per_subaddr.empty() && unused_transfers_indices_per_subaddr.empty()) {
      return std::vector<type::tx::pending_tx>();
    }

    // if empty, put dummy entry so that the front can be referenced later in the loop
    if (unused_dust_indices_per_subaddr.empty()) {
      unused_dust_indices_per_subaddr.push_back({});
    }

    if (unused_transfers_indices_per_subaddr.empty()) {
      unused_transfers_indices_per_subaddr.push_back({});
    }

    // start with an empty tx
    txes.push_back(TX());

    adding_fee = false;
    needed_fee = 0;
    std::vector<std::vector<type::get_tx_outputs_entry>> outs;

    // for rct, since we don't see the amounts, we will try to make all transactions
    // look the same, with 1 or 2 inputs, and 2 outputs. One input is preferable, as
    // this prevents linking to another by provenance analysis, but two is ok if we
    // try to pick outputs not from the same block. We will get two outputs, one for
    // the destination, and one for change.
    LOG_PRINT_L2("checking preferred");

    std::vector<size_t> preferred_inputs;
    {
      // this is used to build a tx that's 1 or 2 inputs, and 2 outputs, which
      // will get us a known fee.
      uint64_t estimated_fee = estimate_fee(2, fake_outs_count, 2, extra.size(), base_fee, fee_multiplier, fee_quantization_mask);
      preferred_inputs = functional::wallet::pick_preferred_rct_inputs
        (
        needed_money + estimated_fee
        , subaddr_account
        , subaddr_indices
        , current_height
        , m_transfers
        );

      if (!preferred_inputs.empty())
      {
        std::string s;

        for (auto i: preferred_inputs) {
          s += boost::lexical_cast<std::string>(i) + " (" + print_money(m_transfers[i].amount()) + ") ";
        }

        LOG_PRINT_L1("Found preferred rct inputs for rct tx: " << s);

        // bring the list of available outputs stored by the same subaddress index to the front of the list
        uint32_t index_minor = m_transfers[preferred_inputs[0]].m_subaddr_index.minor;
        for (size_t i = 1; i < unused_transfers_indices_per_subaddr.size(); ++i)
        {
          if (unused_transfers_indices_per_subaddr[i].first == index_minor)
          {
            std::swap(unused_transfers_indices_per_subaddr[0], unused_transfers_indices_per_subaddr[i]);
            break;
          }
        }
        for (size_t i = 1; i < unused_dust_indices_per_subaddr.size(); ++i)
        {
          if (unused_dust_indices_per_subaddr[i].first == index_minor)
          {
            std::swap(unused_dust_indices_per_subaddr[0], unused_dust_indices_per_subaddr[i]);
            break;
          }
        }
      }
    }
    LOG_PRINT_L2("done checking preferred");

    // while:
    // - we have something to send
    // - or we need to gather more fee
    // - or we have just one input in that tx, which is rct (to try and make all/most rct txes 2/2)
    unsigned int original_output_index = 0;
    std::vector<size_t>& unused_transfers_indices = unused_transfers_indices_per_subaddr[0].second;

    uint64_t accumulated_fee = 0;
    uint64_t accumulated_change = 0;

    while ((!dsts.empty() && dsts[0].amount > 0) || adding_fee || !preferred_inputs.empty()) {
      TX &tx = txes.back();

      LOG_PRINT_L2("Start of loop with " << unused_transfers_indices.size() << ", tx.dsts.size() " << tx.dsts.size());
      LOG_PRINT_L2("unused_transfers_indices: " << functional::helper::strjoin(unused_transfers_indices, " "));
      LOG_PRINT_L2("dsts size " << dsts.size() << ", first " << (dsts.empty() ? "-" : cryptonote::print_money(dsts[0].amount)));
      LOG_PRINT_L2("adding_fee " << adding_fee);

      // if we need to spend money and don't have any left, we fail
      if (unused_transfers_indices.empty()) {
        LOG_PRINT_L2("No more outputs to choose from");
        THROW_WALLET_EXCEPTION
          (
           error::tx_not_possible
           , unlocked_balance
           , needed_money
           , accumulated_fee + needed_fee
           );
      }

      // get a random unspent output and use it to pay part (or all) of the current destination (and maybe next one, etc)
      // This could be more clever, but maybe at the cost of making probabilistic inferences easier
      size_t idx;
      if (!preferred_inputs.empty()) {
        idx = pop_back(preferred_inputs);
        pop_if_present(unused_transfers_indices, idx);
      } else {
        idx = controller::wallet::pop_best_value_from(m_transfers, unused_transfers_indices, tx.selected_transfers);
      }

      const transfer_details &td = m_transfers[idx];
      LOG_PRINT_L2
        (
         "Picking output "
         << idx
         << ", amount "
         << print_money(td.amount())
         << ", ki "
         << td.m_shared_secret_derived_public_key_image
         );

      // add this output to the list to spend
      tx.selected_transfers.push_back(idx);
      uint64_t available_amount = td.amount();

      // clear any fake outs we'd already gathered, since we'll need a new set
      outs.clear();

      if (adding_fee)
      {
        LOG_PRINT_L2("We need more fee, adding it to fee");
        available_for_fee += available_amount;
      }
      else
      {
        while
          (
           !dsts.empty()
           && dsts[0].amount <= available_amount
           && estimate_tx_weight
           (
            tx.selected_transfers.size()
            , fake_outs_count
            , tx.dsts.size()+1
            , extra.size()
            ) < TX_WEIGHT_TARGET(upper_transaction_weight_limit)
           )
          {
            // we can fully pay that destination
            LOG_PRINT_L2
              (
               "We can fully pay "
               << get_account_address_as_str(m_nettype, dsts[0].is_subaddress, dsts[0].addr)
               << " for "
               << print_money(dsts[0].amount)
               );

            tx.add(dsts[0], dsts[0].amount, original_output_index, m_merge_destinations);
            available_amount -= dsts[0].amount;
            dsts[0].amount = 0;
            pop_index(dsts, 0);
            ++original_output_index;
          }

        if
          (
           available_amount > 0
           && !dsts.empty()
           && estimate_tx_weight
           (
            tx.selected_transfers.size()
            , fake_outs_count
            , tx.dsts.size()+1
            , extra.size()
            ) < TX_WEIGHT_TARGET(upper_transaction_weight_limit)
           )
          {
            // we can partially fill that destination
            LOG_PRINT_L2
              (
               "We can partially pay "
               << get_account_address_as_str(m_nettype, dsts[0].is_subaddress, dsts[0].addr)
               << " for "
               << print_money(available_amount)
               << "/"
               <<
               print_money(dsts[0].amount)
               );

            tx.add(dsts[0], available_amount, original_output_index, m_merge_destinations);
            dsts[0].amount -= available_amount;
            available_amount = 0;
          }
      }

      // here, check if we need to sent tx and start a new one
      LOG_PRINT_L2
        (
         "Considering whether to create a tx now, "
         << tx.selected_transfers.size()
         << " inputs, tx limit "
         << upper_transaction_weight_limit
         );

      bool try_tx = false;

      // if we have preferred picks, but haven't yet used all of them, continue
      if (preferred_inputs.empty())
      {
        if (adding_fee)
        {
          // might not actually be enough if adding this output bumps size to next kB, but we need to try
          try_tx = available_for_fee >= needed_fee;
        }
        else
        {
          const size_t estimated_rct_tx_weight =
            estimate_tx_weight(tx.selected_transfers.size(), fake_outs_count, tx.dsts.size()+1, extra.size());

          try_tx = dsts.empty() || (estimated_rct_tx_weight >= TX_WEIGHT_TARGET(upper_transaction_weight_limit));

          THROW_WALLET_EXCEPTION_IF
            (
             try_tx && tx.dsts.empty()
             , error::tx_too_big
             , estimated_rct_tx_weight
             , upper_transaction_weight_limit
             );
        }
      }

      if (try_tx) {
        cryptonote::transaction test_tx;
        pending_tx test_ptx;

        const size_t num_outputs = functional::wallet::get_num_outputs
          (tx.dsts, m_transfers, tx.selected_transfers);
        needed_fee = estimate_fee(tx.selected_transfers.size(), fake_outs_count, num_outputs, extra.size(), base_fee, fee_multiplier, fee_quantization_mask);

        uint64_t inputs = 0, outputs = needed_fee;
        for (size_t idx: tx.selected_transfers) inputs += m_transfers[idx].amount();
        for (const auto &o: tx.dsts) outputs += o.amount;

        if (inputs < outputs)
        {
          LOG_PRINT_L2("We don't have enough for the basic fee, switching to adding_fee");
          adding_fee = true;
          goto skip_tx;
        }

        LOG_PRINT_L2("Trying to create a tx now, with " << tx.dsts.size() << " outputs and " <<
                    tx.selected_transfers.size() << " inputs");

        std::tie(test_ptx, test_tx) = transfer_selected_rct
          (
           outs
           , m_rpc_client
           , tx.dsts
           , tx.selected_transfers
           , fake_outs_count
           , unlock_time
           , needed_fee
           , extra
           , m_transfers
           , account_keys
           , m_subaddresses
           , m_nettype
           );

        auto txBlob = t_serializable_object_to_blob(test_ptx.tx);
        needed_fee = functional::wallet::calculate_fee(test_ptx.tx, txBlob.size(), base_fee, fee_multiplier, fee_quantization_mask);
        available_for_fee = test_ptx.fee + test_ptx.change_dts.amount + (!test_ptx.dust_added_to_fee ? test_ptx.dust : 0);

        LOG_PRINT_L2
          (
           "Made a "
           << functional::wallet::get_weight_string(test_ptx.tx, txBlob.size())
           << " tx"
           << ", with "
           << print_money(available_for_fee)
           << " available for fee ("
           << print_money(needed_fee)
           << " needed)"
           );

        if (needed_fee > available_for_fee && !dsts.empty() && dsts[0].amount > 0)
        {
          // we don't have enough for the fee, but we've only partially paid the current address,
          // so we can take the fee from the paid amount, since we'll have to make another tx anyway
          std::vector<cryptonote::tx_destination_entry>::iterator i;
          i = std::find_if
            (
             tx.dsts.begin()
             , tx.dsts.end()
             , [&](const cryptonote::tx_destination_entry &d) {
               return !memcmp (&d.addr, &dsts[0].addr, sizeof(dsts[0].addr));
             }
             );

          THROW_WALLET_EXCEPTION_IF(i == tx.dsts.end(), error::wallet_internal_error, "paid address not found in outputs");

          if (i->amount > needed_fee)
          {
            uint64_t new_paid_amount = i->amount  - needed_fee;
            LOG_PRINT_L2
              (
               "Adjusting amount paid to "
               << get_account_address_as_str(m_nettype, i->is_subaddress, i->addr)
               << " from "
               << print_money(i->amount)
               << " to "
               << print_money(new_paid_amount)
               << " to accommodate "
               << print_money(needed_fee)
               << " fee"
               );

            dsts[0].amount += i->amount - new_paid_amount;
            i->amount = new_paid_amount;
            test_ptx.fee = needed_fee;
            available_for_fee = needed_fee;
          }
        }

        if (needed_fee > available_for_fee)
        {
          LOG_PRINT_L2("We could not make a tx, switching to fee accumulation");
          adding_fee = true;
        }
        else
        {
          LOG_PRINT_L2
            (
             "We made a tx, adjusting fee and saving it, we need "
             << print_money(needed_fee)
             << " and we have "
             << print_money(test_ptx.fee)
             );

          while (needed_fee > test_ptx.fee) {
            std::tie(test_ptx, test_tx) = transfer_selected_rct
              (
               outs
               , m_rpc_client
               , tx.dsts
               , tx.selected_transfers
               , fake_outs_count
               , unlock_time
               , needed_fee
               , extra
               , m_transfers
               , account_keys
               , m_subaddresses
               , m_nettype
               );
            txBlob = t_serializable_object_to_blob(test_ptx.tx);
            needed_fee = functional::wallet::calculate_fee
              (test_ptx.tx, txBlob.size(), base_fee, fee_multiplier, fee_quantization_mask);

            LOG_PRINT_L2
              (
               "Made an attempt at a final "
               << functional::wallet::get_weight_string(test_ptx.tx, txBlob.size())
               << " tx, with "
               << print_money(test_ptx.fee)
               << " fee  and "
               << print_money(test_ptx.change_dts.amount)
               << " change"
               );
          }

          LOG_PRINT_L2
            (
             "Made a final "
             << functional::wallet::get_weight_string(test_ptx.tx, txBlob.size())
             << " tx, with "
             << print_money(test_ptx.fee)
             << " fee and "
             << print_money(test_ptx.change_dts.amount)
             << " change"
             );

          tx.tx = test_tx;
          tx.ptx = test_ptx;
          tx.weight = get_transaction_weight(test_tx, txBlob.size());
          tx.outs = outs;
          tx.needed_fee = test_ptx.fee;
          accumulated_fee += test_ptx.fee;
          accumulated_change += test_ptx.change_dts.amount;
          adding_fee = false;
          if (!dsts.empty())
          {
            LOG_PRINT_L2("We have more to pay, starting another tx");
            txes.push_back(TX());
            original_output_index = 0;
          }
        }
      }
      
    skip_tx:
      // if unused_*_indices is empty while unused_*_indices_per_subaddr has multiple elements, and if we still have something to pay,
      // pop front of unused_*_indices_per_subaddr and have unused_*_indices point to the front of unused_*_indices_per_subaddr
      if ((!dsts.empty() && dsts[0].amount > 0) || adding_fee)
      {
        if (unused_transfers_indices.empty() && unused_transfers_indices_per_subaddr.size() > 1)
        {
          unused_transfers_indices_per_subaddr.erase(unused_transfers_indices_per_subaddr.begin());
          unused_transfers_indices = unused_transfers_indices_per_subaddr[0].second;
        }
      }
    }

    if (adding_fee)
    {
      LOG_PRINT_L1("We ran out of outputs while trying to gather final fee");
      THROW_WALLET_EXCEPTION
        (
          error::tx_not_possible
          , unlocked_balance
          , needed_money
          , accumulated_fee + needed_fee
          );
    }

    LOG_PRINT_L1
      (
       "Done creating "
       << txes.size()
       << " transactions, "
       << print_money(accumulated_fee)
       << " total fee, "
       << print_money(accumulated_change)
       << " total change"
       );

    for (auto& tx: txes)
    {
      const auto[test_ptx, test_tx] =
        transfer_selected_rct
        (
          tx.outs
          , m_rpc_client
          , tx.dsts
          , tx.selected_transfers
          , fake_outs_count
          , unlock_time
          , tx.needed_fee
          , extra
          , m_transfers
          , account_keys
          , m_subaddresses
          , m_nettype
          );

      auto txBlob = t_serializable_object_to_blob(test_ptx.tx);
      tx.tx = test_tx;
      tx.ptx = test_ptx;
      tx.weight = get_transaction_weight(test_tx, txBlob.size());
    }

    std::vector<type::tx::pending_tx> ptx_vector;
    for (size_t i = 0; const auto& tx: txes)
    {
      i++;
      uint64_t tx_money = 0;
      for (size_t idx: tx.selected_transfers)
        tx_money += m_transfers[idx].amount();
      LOG_PRINT_L1
        (
        "  Transaction " << i << "/" << txes.size()
        << " " << get_transaction_hash(tx.ptx.tx) << ": " << functional::wallet::get_weight_string(tx.weight)
        << ", sending " << print_money(tx_money) << " in " << tx.selected_transfers.size()
        << " outputs to " << tx.dsts.size() << " destination(s)"
        << ", including " << print_money(tx.ptx.fee) << " fee"
        << ", " << print_money(tx.ptx.change_dts.amount) << " change"
        );
      ptx_vector.push_back(tx.ptx);
    }

    const bool valid_tx = sanity_check
      (
       ptx_vector
       , original_dsts
       , m_transfers
       , m_subaddresses
       , account_keys.m_view_secret_key
       , m_nettype
       );

    THROW_WALLET_EXCEPTION_IF
      (
       !valid_tx
      , error::wallet_internal_error
      , "Created transaction(s) failed sanity check"
      );

    // if we made it this far, we're OK to actually send the transactions
    return ptx_vector;
  }

} // wallet
} // controller
} // logic
} // wallet
