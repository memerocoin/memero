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

#include "cryptonote/basic/functional/base.hpp"

#include "cryptonote/basic/type/string_blob_type.hpp"
#include "cryptonote/basic/type/tx_extra.hpp"
#include "cryptonote/basic/type/subaddress_index.hpp"
#include "cryptonote/basic/controller/account.h"

#include "tools/epee/include/blob.hpp"

namespace cryptonote
{

  struct subaddress_receive_info
  {
    const subaddress_index index;
    const crypto::ecdh_shared_secret tx_output_shared_secret;
  };



  crypto::hash get_transaction_prefix_hash(const transaction_prefix& tx);

  std::optional<std::pair<keypair, crypto::key_image>>
  derive_with_internal_checking_output_spend_key_pair_and_key_image
  (
   const account_keys ack
   , const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses
   , const crypto::public_key out_key
   , const std::optional<crypto::public_key> tx_public_key
   , const std::span<const crypto::public_key> output_public_keys
   , const size_t real_output_index
   );

  std::optional<std::pair<keypair, crypto::key_image>>
  derive_output_spend_key_pair_and_key_image
  (
   const account_keys ack
   , const crypto::public_key out_key
   , const crypto::ecdh_shared_secret recv_tx_output_shared_secret
   , const size_t real_output_index
   , const subaddress_index received_index
   );

  std::optional<subaddress_receive_info> check_output_for_subaddresses
  (
   const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses
   , const crypto::public_key tx_out_key
   , const crypto::ecdh_shared_secret tx_output_shared_secret
   , const size_t output_index
   );

  crypto::hash get_blob_hash(const string_blob blob);
  crypto::hash get_blob_hash(const string_blob_view blob);
  std::string short_hash_str(const crypto::hash h);

  //---------------------------------------------------------------
  crypto::hash calculate_transaction_prunable_hash
  (
   const transaction& t
   , const cryptonote::string_blob_view blob
   );

  //---------------------------------------------------------------
  template<class t_object>
  std::optional<string_blob> maybe_to_blob(const t_object& to)
  {
    std::ostringstream ss;
    binary_archive<true> ba(ss);
    const bool r = ::serialization::serialize(ba, const_cast<t_object&>(to));
    if (r) {
      return ss.str();
    } else {
      return {};
    }
  }
  //---------------------------------------------------------------
  template<class t_object>
  string_blob t_serializable_object_to_blob(const t_object& to)
  {
    const auto b = maybe_to_blob(to);
    if (!b) {
      throw std::runtime_error("failed to serialize object to blob");
    }
    return *b;
  }


  template<class t_object>
  std::optional<t_object> maybe_from_blob(const string_blob_view b_blob, const t_object& dummy)
  {
    t_object x;
    std::stringstream ss;
    ss << b_blob;
    binary_archive<false> ba(ss);
    const bool r = ::serialization::serialize(ba, x);
    if (r) {
      return x;
    } else {
      return {};
    }
  }
  //---------------------------------------------------------------
  template<class t_object>
  crypto::hash get_object_hash(const t_object& o)
  {
    return get_blob_hash(t_serializable_object_to_blob(o));
  }
  //---------------------------------------------------------------
  template<class t_object>
  size_t get_object_blobsize(const t_object& o)
  {
    string_blob b = t_serializable_object_to_blob(o);
    return b.size();
  }
  //---------------------------------------------------------------
  template <typename T>
  std::string obj_to_json_str(const T& obj)
  {
    std::ostringstream ss;
    json_archive<true> ar(ss, true);
    bool r = ::serialization::serialize(ar, const_cast<T&>(obj));
    LOG_ERROR_AND_RETURN_UNLESS
      (r, "", "obj_to_json_str failed: serialization::serialize returned false");
    return ss.str();
  }

  crypto::secret_key encrypt_key(const crypto::secret_key key, const epee::wipeable_string &passphrase);
  crypto::secret_key decrypt_key(const crypto::secret_key key, const epee::wipeable_string &passphrase);

  crypto::hash get_tx_tree_hash(const std::span<const crypto::hash> tx_hashes);
  crypto::hash get_tx_tree_hash(const block& b);

  uint64_t get_tx_fee(const transaction& tx);
  uint64_t get_transaction_weight(const transaction &tx);

  uint64_t get_block_height(const block& b);

  bool check_inputs_types_supported(const transaction& tx);
  bool check_outs_valid(const transaction& tx);

  bool check_money_overflow(const transaction& tx);
  bool check_outs_overflow(const transaction& tx);
  bool check_inputs_overflow(const transaction& tx);

  string_blob get_mining_blob(const block& b);
  string_blob get_mining_blob_head(const block& b);
  string_blob get_mining_blob_tail(const block& b);

  std::optional<crypto::hash> get_maybe_block_hash(const block& b);
  crypto::hash get_block_hash(const block& b);

  std::vector<uint64_t> relative_output_offsets_to_absolute(const std::vector<uint64_t>& off);
  std::vector<uint64_t> absolute_output_offsets_to_relative(const std::vector<uint64_t>& off);

  crypto::hash get_transaction_hash(const transaction& t);

  crypto::hash get_mining_hash(const block& b);

  uint64_t get_tx_outputs_money_amount(const transaction& tx);

  std::optional<transaction> maybe_tx_from_blob(const string_blob_view tx_blob);
  std::optional<transaction_prefix> maybe_tx_prefix_from_blob(const string_blob_view tx_blob);

  std::optional<std::pair<transaction, crypto::hash>>
  maybe_tx_and_hash_from_blob(const string_blob_view tx_blob);

  string_blob block_to_blob(const block& b);
  std::optional<string_blob> maybe_block_to_blob(const block& b);
  string_blob tx_to_blob(const transaction& b);
  std::optional<string_blob> maybe_tx_to_blob(const transaction& tx);

  uint64_t get_inputs_money_amount(const transaction& tx);

  std::optional<block> maybe_block_from_blob(const string_blob_view b_blob);

  std::optional<std::pair<block, crypto::hash>>
  maybe_block_and_hash_from_blob(const string_blob_view b_blob);

}


#define CHECKED_GET_SPECIFIC_VARIANT(variant_var, specific_type, variable_name, fail_return_val) \
  LOG_ERROR_AND_RETURN_UNLESS                                           \
  (                                                                     \
   variant_var.type() == typeid(specific_type)                          \
   , fail_return_val                                                    \
   , "wrong variant type: "                                             \
   << variant_var.type().name()                                         \
   << ", expected "                                                     \
   << typeid(specific_type).name());                                    \
  specific_type& variable_name = boost::get<specific_type>(variant_var);
