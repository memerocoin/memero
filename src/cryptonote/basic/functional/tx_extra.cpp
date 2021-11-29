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

#include "tx_extra.hpp"

#include "tools/epee/include/string_tools.h"
#include "tools/serialization/string.h" // don't remove, or face core dump

#include "math/ringct/pseudo_functional/ringCT.hpp"

#include "math/blockchain/functional/subaddress.hpp"

#include <boost/algorithm/string.hpp>





namespace cryptonote
{
  //---------------------------------------------------------------
  std::optional<std::vector<tx_extra_field>> parse_tx_extra(const epee::blob::span tx_extra)
  {
    std::vector<tx_extra_field> tx_extra_fields;

    if(tx_extra.empty())
      return tx_extra_fields;

    std::string extra_str = epee::string_tools::blob_to_string(tx_extra);
    std::istringstream iss(extra_str);
    binary_archive<false> ar(iss);

    bool eof = false;
    while (!eof)
    {
      tx_extra_field field;
      bool r = ::do_serialize(ar, field);
      LOG_WITH_LEVEL_3_AND_RETURN_UNLESS
        (
         r
         , {}
         , "failed to deserialize extra field. extra = "
         << epee::string_tools::buff_to_hex_nodelimer(epee::string_tools::blob_to_string(tx_extra))
         );
      tx_extra_fields.push_back(field);

      std::ios_base::iostate state = iss.rdstate();
      eof = (EOF == iss.peek());
      iss.clear(state);
    }
    LOG_WITH_LEVEL_3_AND_RETURN_UNLESS
      (
       ::serialization::check_stream_state(ar)
       , {}
       , "failed to deserialize extra field. extra = "
       << epee::string_tools::buff_to_hex_nodelimer(epee::string_tools::blob_to_string(tx_extra))
       );

    return tx_extra_fields;
  }

  //---------------------------------------------------------------
  std::optional<crypto::public_key> get_tx_ecdh_public_key_from_extra(const epee::blob::span tx_extra)
  {
    const auto maybe_tx_extra_fields = parse_tx_extra(tx_extra);

    if (!maybe_tx_extra_fields) return {};

    const auto r = find_tx_extra_field_by_type<tx_extra_tx_public_key>(*maybe_tx_extra_fields);
    if(!r) {
      return {};
    }

    const tx_extra_tx_public_key pub_key_field = *r;

    const auto maybe_safe_point = maybeSafePoint(pub_key_field.pub_key_unsafe);

    if (maybe_safe_point) {
      return crypto::p2pk(*maybe_safe_point);
    } else {
      return {};
    }

  }

  //---------------------------------------------------------------
  std::optional<std::vector<crypto::public_key>>
  get_output_ecdh_public_keys_from_extra(const epee::blob::span tx_extra)
  {
    const auto maybe_tx_extra_fields = parse_tx_extra(tx_extra);

    if (!maybe_tx_extra_fields) return {};

    // find corresponding field
    const auto r =
      find_tx_extra_field_by_type<tx_extra_output_ecdh_public_keys>(*maybe_tx_extra_fields);
    if(!r) {
      return {};
    }
    const tx_extra_output_ecdh_public_keys output_pub_keys_unsafe = *r; 

    std::vector<crypto::public_key> output_pub_keys;

    std::for_each
      (
       output_pub_keys_unsafe.pub_keys_unsafe.begin()
       , output_pub_keys_unsafe.pub_keys_unsafe.end()
       , [&output_pub_keys](const auto& k) {
         const auto maybe_safe_point = crypto::maybeSafePoint(k);
         if (maybe_safe_point) {
           output_pub_keys.push_back(crypto::p2pk(*maybe_safe_point));
         }
       }
       );

    if (output_pub_keys.size() != output_pub_keys_unsafe.pub_keys_unsafe.size()) {
      return {};
    } else {
      return output_pub_keys;
    }
  }

  std::optional<std::vector<crypto::public_key>> get_all_output_ecdh_public_keys_from_extra
  (
   const epee::blob::span tx_extra
   , const size_t output_count
   )
  {
    const auto maybe_pub_keys = get_output_ecdh_public_keys_from_extra(tx_extra);

    if (maybe_pub_keys && maybe_pub_keys->size() == output_count) {
      return *maybe_pub_keys;
    }

    const auto x = get_tx_ecdh_public_key_from_extra(tx_extra);

    if(x) {
      std::vector<crypto::public_key> dups(output_count);
      std::fill
        (
         dups.begin()
         , dups.end()
         , *x
         );
      return dups;
    }

    return {};
  }

  //---------------------------------------------------------------
  std::optional<std::vector<uint8_t>> remove_field_from_tx_extra
  (
   const std::vector<uint8_t> tx_extra_in
   , const std::type_info& type
   )
  {
    std::vector<uint8_t> tx_extra = tx_extra_in;

    if (tx_extra.empty())
      return tx_extra;

    std::string extra_str = epee::string_tools::blob_to_string(tx_extra);
    std::istringstream iss(extra_str);
    binary_archive<false> ar(iss);
    std::ostringstream oss;
    binary_archive<true> newar(oss);

    bool eof = false;
    while (!eof)
    {
      tx_extra_field field;
      bool r = ::do_serialize(ar, field);
      LOG_WITH_LEVEL_2_AND_RETURN_UNLESS
        (
         r
         , {}
         , "failed to deserialize extra field. extra = "
         << epee::string_tools::buff_to_hex_nodelimer(epee::string_tools::blob_to_string(tx_extra))
         );
      if (field.type() != type)
        ::do_serialize(newar, field);

      std::ios_base::iostate state = iss.rdstate();
      eof = (EOF == iss.peek());
      iss.clear(state);
    }
    LOG_WITH_LEVEL_2_AND_RETURN_UNLESS
      (
       ::serialization::check_stream_state(ar)
       , {}
       , "failed to deserialize extra field. extra = "
       << epee::string_tools::buff_to_hex_nodelimer(epee::string_tools::blob_to_string(tx_extra))
       );
    std::string s = oss.str();
    tx_extra.reserve(s.size());
    std::copy(s.begin(), s.end(), std::back_inserter(tx_extra));
    return tx_extra;
  }

  //---------------------------------------------------------------
  std::vector<uint8_t> add_tx_ecdh_public_key_to_extra
  (
   const std::vector<uint8_t> tx_extra_in
   , const crypto::public_key tx_pub_key
   )
  {
    std::vector<uint8_t> tx_extra = tx_extra_in;
    tx_extra.push_back(TX_EXTRA_TAG_TX_PUBKEY);
    tx_extra.insert(tx_extra.end(), tx_pub_key.data.begin(), tx_pub_key.data.end());
    return tx_extra;
  }

  //---------------------------------------------------------------
  std::vector<uint8_t> add_output_ecdh_public_keys_to_extra
  (
   const std::vector<uint8_t> tx_extra_in
   , const std::span<const crypto::public_key> output_pub_keys
   )
  {
    std::vector<uint8_t> tx_extra = tx_extra_in;
    // convert to variant
    std::vector<crypto::ec_point_unsafe> output_pub_keys_unsafe;

    std::transform
      (
       output_pub_keys.begin()
       , output_pub_keys.end()
       , std::back_inserter(output_pub_keys_unsafe)
       , [](const auto&x) { return x; }
       );

    tx_extra_field field = tx_extra_output_ecdh_public_keys{ output_pub_keys_unsafe };
    // serialize
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    bool r = ::do_serialize(ar, field);

    LOG_WITH_LEVEL_1_AND_RETURN_UNLESS
      (r, tx_extra_in, "failed to serialize tx extra tx output pub keys");

    // append
    std::string tx_extra_str = oss.str();
    std::copy(tx_extra_str.begin(), tx_extra_str.end(), std::back_inserter(tx_extra));
    return tx_extra;
  }
}
