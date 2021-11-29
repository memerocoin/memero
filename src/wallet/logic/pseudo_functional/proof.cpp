
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


#include "cryptonote/basic/functional/tx_extra.hpp"

#include "wallet/api/wallet_errors.h"

#include "tools/common/base58.h"
#include "tools/epee/include/string_tools.h"

namespace wallet {
namespace logic {
namespace pseudo_functional {
namespace proof {

  const std::optional<std::vector<size_t>> verify_output_ecdh_signatures
  (
   const cryptonote::transaction &tx
   , const cryptonote::spend_view_public_keys &address
   , const bool is_subaddress
   , const std::string &message
   , const std::string &sig_str
   ) {

    const std::string header = std::string(config::HASH_KEY_TX_OUTPUT_SIGNATURES_V1);

    const size_t header_len = header.size();
    THROW_WALLET_EXCEPTION_IF
      (
       sig_str.size() < header_len || sig_str.substr(0, header_len) != header
       , tools::error::wallet_internal_error
       , "Signature header check error"
       );

    // decode base58
    std::vector<crypto::schnorr_signature> sigs;
    const crypto::schnorr_signature dummySig{};
    const size_t sig_len = tools::base58::encode(epee::string_tools::blob_to_string(epee::pod_to_span(dummySig))).size();

    const size_t num_sigs = (sig_str.size() - header_len) / sig_len;

    THROW_WALLET_EXCEPTION_IF
      (
       sig_str.size() != header_len + num_sigs * sig_len
       , tools::error::wallet_internal_error
       , "Wrong signature size"
       );

    for (size_t i = 0; i < num_sigs; ++i)
    {
      std::string sig_decoded;
      const size_t offset = header_len + i * sig_len;

      THROW_WALLET_EXCEPTION_IF
        (
         !tools::base58::decode(sig_str.substr(offset, sig_len), sig_decoded)
         , tools::error::wallet_internal_error
         , "Signature decoding error"
         );

      THROW_WALLET_EXCEPTION_IF
        (
         sizeof(crypto::schnorr_signature) != sig_decoded.size()
         , tools::error::wallet_internal_error
         , "Signature decoding error"
         );

      constexpr size_t schnorr_size = sizeof(crypto::schnorr_signature);

      crypto::schnorr_signature_unnormalized sig_unsafe{};

      memcpy(&sig_unsafe, sig_decoded.data(), schnorr_size);


      // reject invalid keys
      const auto maybeSig = maybe_valid_schnorr_signature(sig_unsafe);
      if (!maybeSig) return {};

      sigs.push_back(*maybeSig);
    }

    const epee::blob::data message_data = epee::string_tools::string_to_blob(message);
    const crypto::hash message_hash = crypto::sha3(message_data);

    // check signature
    std::vector<int> good_signature(num_sigs, 0);

    const auto maybe_output_ecdh_public_keys =
      get_all_output_ecdh_public_keys_from_extra(tx, tx.vout.size());

    if (!maybe_output_ecdh_public_keys) return {};
    const auto output_ecdh_public_keys = *maybe_output_ecdh_public_keys;

    std::vector<size_t> found_indices;
    for (size_t i = 0; i < output_ecdh_public_keys.size(); ++i)
    {
      const std::optional<crypto::public_key> base =
        is_subaddress
        ? std::optional<crypto::public_key>(address.m_spend_public_key)
        : std::nullopt
        ;

      const bool good_signature = crypto::verify_output_ecdh_signatures
        (message_hash, output_ecdh_public_keys[i], base, sigs[i]);

      if (good_signature) {
        found_indices.push_back(i);
      }
      else {
        LOG_DEBUG("bad signature for tx output pub key at index: " << i);
      }
    }

    if (found_indices.empty()) {
      return {};
    } else {
      return found_indices;
    }
  }


} // proof
} // pseudo_functional
} // logic
} // wallet
