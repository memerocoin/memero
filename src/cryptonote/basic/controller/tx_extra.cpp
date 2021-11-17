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

#include "math/ringct/pseudo_functional/rctSigs.hpp"

#include "cryptonote/basic/functional/subaddress.hpp"

#include <boost/algorithm/string.hpp>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "cn"

using namespace constant;

namespace cryptonote
{

  //---------------------------------------------------------------
  template<typename T>
  bool pick(binary_archive<true> &ar, std::vector<tx_extra_field> &fields, uint8_t tag)
  {
    std::vector<tx_extra_field>::iterator it;
    while ((it = std::find_if(fields.begin(), fields.end(), [](const tx_extra_field &f) { return f.type() == typeid(T); })) != fields.end())
      {
        bool r = ::do_serialize(ar, tag);
        LOG_WITH_LEVEL_1_AND_RETURN_UNLESS(r, false, "failed to serialize tx extra field");
        r = ::do_serialize(ar, boost::get<T>(*it));
        LOG_WITH_LEVEL_1_AND_RETURN_UNLESS(r, false, "failed to serialize tx extra field");
        fields.erase(it);
      }
    return true;
  }

  //---------------------------------------------------------------
  bool sort_tx_extra(const std::span<const uint8_t> tx_extra, std::vector<uint8_t> &sorted_tx_extra, bool allow_partial)
  {
    std::vector<tx_extra_field> tx_extra_fields;

    if(tx_extra.empty())
    {
      sorted_tx_extra.clear();
      return true;
    }

    std::string extra_str = epee::string_tools::blob_to_string(tx_extra);
    std::istringstream iss(extra_str);
    binary_archive<false> ar(iss);

    bool eof = false;
    size_t processed = 0;
    while (!eof)
    {
      tx_extra_field field;
      bool r = ::do_serialize(ar, field);
      if (!r)
      {
        LOG_DEBUG
          (
           "sort tx extra: failed to deserialize extra field. extra = "
           << epee::string_tools::buff_to_hex_nodelimer(epee::string_tools::blob_to_string(tx_extra))
           );

        if (!allow_partial)
          return false;
        break;
      }
      tx_extra_fields.push_back(field);
      processed = iss.tellg();

      std::ios_base::iostate state = iss.rdstate();
      eof = (EOF == iss.peek());
      iss.clear(state);
    }
    if (!::serialization::check_stream_state(ar))
    {
      LOG_DEBUG
        (
         "sort tx extra: failed to deserialize extra field. extra = "
         << epee::string_tools::buff_to_hex_nodelimer(epee::string_tools::blob_to_string(tx_extra))
         );
      if (!allow_partial)
        return false;
    }
    LOG_TRACE("Sorted " << processed << "/" << tx_extra.size());

    std::ostringstream oss;
    binary_archive<true> nar(oss);

    // sort by:
    if (!pick<tx_extra_tx_public_key>(nar, tx_extra_fields, TX_EXTRA_TAG_TX_PUBKEY)) return false;
    if (!pick<tx_extra_tx_output_public_keys>(nar, tx_extra_fields, TX_EXTRA_TAG_TX_OUTPUT_PUBKEYS)) return false;

    // if not empty, someone added a new type and did not add a case above
    if (!tx_extra_fields.empty())
    {
      LOG_ERROR("tx_extra_fields not empty after sorting, someone forgot to add a case above");
      return false;
    }

    std::string oss_str = oss.str();
    if (allow_partial && processed < tx_extra.size())
    {
      LOG_DEBUG("Appending unparsed data");
      oss_str += epee::string_tools::blob_to_string(std::span(tx_extra).subspan(processed, tx_extra.size() - processed));
    }
    sorted_tx_extra = std::vector<uint8_t>(oss_str.begin(), oss_str.end());
    return true;
  }
  //---------------------------------------------------------------
  bool add_tx_pub_key_to_extra(transaction& tx, const crypto::public_key& tx_pub_key)
  {
    return add_tx_pub_key_to_extra(tx.extra, tx_pub_key);
  }
  //---------------------------------------------------------------
  bool add_tx_pub_key_to_extra(std::vector<uint8_t>& tx_extra, const crypto::public_key& tx_pub_key)
  {
    tx_extra.push_back(TX_EXTRA_TAG_TX_PUBKEY);
    tx_extra.insert(tx_extra.end(), tx_pub_key.data.begin(), tx_pub_key.data.end());
    return true;
  }

  //---------------------------------------------------------------
  bool add_tx_output_keys_to_extra(std::vector<uint8_t>& tx_extra, const std::span<const crypto::public_key> output_pub_keys)
  {
    // convert to variant
    std::vector<crypto::ec_point_unsafe> output_pub_keys_unsafe;

    std::transform
      (
       output_pub_keys.begin()
       , output_pub_keys.end()
       , std::back_inserter(output_pub_keys_unsafe)
       , [](const auto&x) { return x; }
       );

    tx_extra_field field = tx_extra_tx_output_public_keys{ output_pub_keys_unsafe };
    // serialize
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    bool r = ::do_serialize(ar, field);
    LOG_WITH_LEVEL_1_AND_RETURN_UNLESS(r, false, "failed to serialize tx extra tx output pub keys");

    // append
    std::string tx_extra_str = oss.str();
    std::copy(tx_extra_str.begin(), tx_extra_str.end(), std::back_inserter(tx_extra));
    return true;
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
}
