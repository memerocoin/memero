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

#include "../blobdatatype.h"
#include "../cryptonote_basic_impl.h"
#include "../tx_extra.h"
#include "../account.h"
#include "../subaddress_index.h"

#include "tools/epee/include/blob.hpp"

namespace cryptonote
{

  struct subaddress_receive_info
  {
    subaddress_index index;
    crypto::tx_ecdh_shared_secret tx_shared_secret;
  };



  crypto::hash get_transaction_prefix_hash(const transaction_prefix& tx);

  std::optional<std::pair<keypair, crypto::key_image>> derive_key_image_helper
  (
   const account_keys& ack
   , const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses
   , const crypto::public_key& out_key
   , const std::optional<crypto::public_key>& tx_public_key
   , const std::vector<crypto::public_key>& additional_tx_public_keys
   , const size_t real_output_index
   );

  std::optional<std::pair<keypair, crypto::key_image>> derive_key_image_helper_precomp
  (
   const account_keys& ack
   , const crypto::public_key& out_key
   , const crypto::tx_ecdh_shared_secret& recv_tx_shared_secret
   , const size_t real_output_index
   , const subaddress_index& received_index
   );

  std::optional<std::vector<tx_extra_field>> parse_tx_extra(const epee::blob::span tx_extra);

  std::optional<crypto::public_key> get_tx_pub_key_from_extra(const std::vector<uint8_t>& tx_extra);
  std::optional<crypto::public_key> get_tx_pub_key_from_extra(const transaction_prefix& tx);
  std::optional<crypto::public_key> get_tx_pub_key_from_extra(const transaction& tx);

  bool is_out_to_acc
  (
   const account_keys& acc
   , const txout_to_key& out_key
   , const std::optional<crypto::public_key>& tx_pub_key
   , const std::vector<crypto::public_key>& additional_tx_pub_keys
   , const size_t output_index
   );

  std::optional<subaddress_receive_info> is_out_to_acc_precomp
  (
   const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses
   , const crypto::public_key& tx_out_key
   , const std::optional<crypto::tx_ecdh_shared_secret>& tx_shared_secret
   , const std::vector<crypto::tx_ecdh_shared_secret>& tx_shared_secrets
   , const size_t output_index
   );

  crypto::hash get_blob_hash(const blobdata& blob);
  crypto::hash get_blob_hash(const blobdata_ref& blob);
  std::string short_hash_str(const crypto::hash& h);

  bool get_transaction_hash(const transaction& t, crypto::hash& res);
  bool get_transaction_hash(const transaction& t, crypto::hash& res);
  bool get_transaction_hash(const transaction& t, crypto::hash& res);
  crypto::hash get_transaction_hash(const transaction& t);

}
