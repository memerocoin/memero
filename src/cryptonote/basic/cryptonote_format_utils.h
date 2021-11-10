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

#include "type/blobdatatype.hpp"
#include "cryptonote_basic_impl.h"
#include "type/tx_extra.hpp"
#include "account.h"
#include "type/subaddress_index.hpp"

#include "functional/format_utils.hpp"




#include <boost/multiprecision/cpp_int.hpp>



namespace cryptonote
{
  //---------------------------------------------------------------

  bool parse_and_validate_tx_prefix_from_blob(const blobdata_ref tx_blob, transaction_prefix& tx);
  bool parse_and_validate_tx_from_blob(const blobdata_ref tx_blob, transaction& tx, crypto::hash& tx_hash, crypto::hash& tx_prefix_hash);
  bool parse_and_validate_tx_from_blob(const blobdata_ref tx_blob, transaction& tx, crypto::hash& tx_hash);
  bool parse_and_validate_tx_from_blob(const blobdata_ref tx_blob, transaction& tx);
  bool parse_and_validate_tx_base_from_blob(const blobdata_ref tx_blob, transaction& tx);

  template<typename T>
  bool find_tx_extra_field_by_type(const std::vector<tx_extra_field>& tx_extra_fields, T& field, size_t index = 0)
  {
    auto it = std::find_if(tx_extra_fields.begin(), tx_extra_fields.end(), [&index](const tx_extra_field& f) { return typeid(T) == f.type() && !index--; });
    if(tx_extra_fields.end() == it)
      return false;

    field = boost::get<T>(*it);
    return true;
  }

  bool sort_tx_extra(const std::vector<uint8_t>& tx_extra, std::vector<uint8_t> &sorted_tx_extra, bool allow_partial = false);
  bool add_tx_pub_key_to_extra(transaction& tx, const crypto::public_key& tx_pub_key);
  bool add_tx_pub_key_to_extra(transaction_prefix& tx, const crypto::public_key& tx_pub_key);
  bool add_tx_pub_key_to_extra(std::vector<uint8_t>& tx_extra, const crypto::public_key& tx_pub_key);

  bool add_tx_output_keys_to_extra(std::vector<uint8_t>& tx_extra, const std::vector<crypto::public_key>& output_pub_keys);
  bool remove_field_from_tx_extra(std::vector<uint8_t>& tx_extra, const std::type_info &type);


  bool parse_and_validate_block_from_blob(const blobdata_ref b_blob, block& b, crypto::hash *block_hash);
  bool parse_and_validate_block_from_blob(const blobdata_ref b_blob, block& b);
  bool parse_and_validate_block_from_blob(const blobdata_ref b_blob, block& b, crypto::hash &block_hash);
  bool get_inputs_money_amount(const transaction& tx, uint64_t& money);

  bool parse_amount(uint64_t& amount, const std::string& str_amount);

  void set_default_decimal_point(unsigned int decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT);
  unsigned int get_default_decimal_point();
  std::string get_unit(unsigned int decimal_point = -1);
  std::string print_money_64(uint64_t amount, unsigned int decimal_point = -1);
  std::string print_money(uint64_t amount, unsigned int decimal_point = -1);
  std::string print_money_128(const boost::multiprecision::uint128_t &amount, unsigned int decimal_point = -1);
  std::string print_money(const boost::multiprecision::uint128_t &amount, unsigned int decimal_point = -1);
  //---------------------------------------------------------------
  template<class t_object>
  bool t_serializable_object_from_blob(t_object& to, const blobdata& b_blob)
  {
    std::stringstream ss;
    ss << b_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, to);
    return r;
  }
  //---------------------------------------------------------------
  blobdata block_to_blob(const block& b);
  bool block_to_blob(const block& b, blobdata& b_blob);
  blobdata tx_to_blob(const transaction& b);
  bool tx_to_blob(const transaction& b, blobdata& b_blob);

  void get_hash_stats(uint64_t &tx_hashes_calculated, uint64_t &tx_hashes_cached, uint64_t &block_hashes_calculated, uint64_t & block_hashes_cached);

#define CHECKED_GET_SPECIFIC_VARIANT(variant_var, specific_type, variable_name, fail_return_val) \
  LOG_ERROR_AND_RETURN_UNLESS(variant_var.type() == typeid(specific_type), fail_return_val, "wrong variant type: " << variant_var.type().name() << ", expected " << typeid(specific_type).name()); \
  specific_type& variable_name = boost::get<specific_type>(variant_var);


}
