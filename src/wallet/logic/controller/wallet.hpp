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

#include "wallet/logic/type/wallet.hpp"
#include "wallet/logic/type/typedef.hpp"

#include "wallet/api/rpc_client.h"

#include "cryptonote/tx/pseudo_functional/tx_utils.hpp"

namespace {

  template<typename T>
  T pop_index(std::vector<T>& vec, size_t idx)
  {
    LOG_ERROR_AND_RETURN_UNLESS(!vec.empty(), T(), "Vector must be non-empty");
    LOG_ERROR_AND_RETURN_UNLESS(idx < vec.size(), T(), "idx out of bounds");

    T res = vec[idx];
    vec.erase(std::next(vec.begin(), idx));

    return res;
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
   );

  bool save_to_file
  (
   const std::string& path_to_file
   , const std::string& raw
   );

  bool load_from_file
  (
   const std::string& path_to_file
   , std::string& target_str
   );

  void print_source_entry(const cryptonote::tx_source_entry& src);

  bool verify_password(const std::string& keys_file_name, const epee::wipeable_string& password, bool no_spend_key, uint64_t kdf_rounds);

  size_t pop_best_value_from
  (
   const ::wallet::logic::type::wallet::transfer_container_span transfers
   , std::vector<size_t> &unused_indices
   , const std::span<size_t> selected_transfers
   , bool smallest = false
   );

  std::vector<std::vector<type::get_tx_outputs_entry>> get_tx_outputs
  (
   const std::vector<size_t> selected_transfers
   , const size_t fake_outputs_count
   , const tools::RPC_Client m_rpc_client
   , const type::wallet::transfer_container_span m_transfers
   );

  std::pair<type::tx::pending_tx, cryptonote::transaction> transfer_selected_rct
  (
   std::vector<std::vector<type::get_tx_outputs_entry>> &outs
   , const tools::RPC_Client m_rpc_client
   , const std::vector<cryptonote::tx_destination_entry> dsts
   , const std::vector<size_t> selected_transfers
   , const size_t fake_outputs_count
   , const uint64_t unlock_height
   , const uint64_t fee
   , const std::vector<uint8_t> extra
   , const type::wallet::transfer_container_span m_transfers
   , const cryptonote::account_keys account_keys
   , const serializable_unordered_map<crypto::public_key, cryptonote::subaddress_index>& m_subaddresses
   , const cryptonote::network_type m_nettype
   );


  bool sanity_check
  (
   const std::span<const type::tx::pending_tx> ptx_vector
   , const std::span<const cryptonote::tx_destination_entry> dsts
   , const type::wallet::transfer_container_span m_transfers
   , const serializable_unordered_map<crypto::public_key, cryptonote::subaddress_index>& m_subaddresses
   , const crypto::secret_key m_view_secret_key
   , const cryptonote::network_type m_nettype
   );

  std::vector<type::tx::pending_tx> create_transactions
  (
   const std::vector<cryptonote::tx_destination_entry> dsts_vec
   , const size_t fake_outs_count
   , const uint64_t unlock_height
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
   );

} // wallet
} // controller
} // logic
} // wallet
