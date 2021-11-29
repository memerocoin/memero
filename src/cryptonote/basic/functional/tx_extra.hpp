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

#include "cryptonote/basic/type/string_blob_type.hpp"
#include "cryptonote/basic/functional/base.hpp"
#include "cryptonote/basic/type/tx_extra.hpp"
#include "math/blockchain/functional/subaddress_index.hpp"

#include "tools/epee/include/blob.hpp"

namespace cryptonote
{
  //---------------------------------------------------------------
  template<typename T>
  std::optional<T> find_tx_extra_field_by_type
  (const std::span<const tx_extra_field> tx_extra_fields, const T&)
  {
    const auto it = std::find_if
      (
       tx_extra_fields.begin()
       , tx_extra_fields.end()
       , [](const tx_extra_field& f) {
         return typeid(T) == f.type();
       }
       );

    if(tx_extra_fields.end() == it)
      return {};

    return boost::get<T>(*it);
  }

  std::optional<std::vector<tx_extra_field>> parse_tx_extra(const epee::blob::span tx_extra);

  std::optional<crypto::public_key> get_tx_ecdh_public_key_from_extra(const epee::blob::span tx_extra);
  std::optional<crypto::public_key> get_tx_ecdh_public_key_from_extra(const transaction_prefix& tx);
  std::optional<crypto::public_key> get_tx_ecdh_public_key_from_extra(const transaction& tx);

  std::optional<std::vector<crypto::public_key>> get_all_output_ecdh_public_keys_from_extra
  (
   const transaction& tx
   , const size_t output_count
   );

  std::optional<std::vector<crypto::public_key>>
  get_output_ecdh_public_keys_from_extra(const epee::blob::span tx_extra);

  std::optional<std::vector<crypto::public_key>>
  get_output_ecdh_public_keys_from_extra(const transaction_prefix& tx);

  std::optional<std::vector<uint8_t>> remove_field_from_tx_extra
  (const std::vector<uint8_t> tx_extra, const std::type_info& type);

  transaction add_tx_ecdh_public_key_to_extra(const transaction& tx_in, const crypto::public_key tx_pub_key);
  std::vector<uint8_t> add_tx_ecdh_public_key_to_extra
  (const std::vector<uint8_t>& tx_extra_in, const crypto::public_key tx_pub_key);

  std::vector<uint8_t> add_output_ecdh_public_keys_to_extra
  (const std::vector<uint8_t>& tx_extra_in, const std::span<const crypto::public_key> output_pub_keys);
}
