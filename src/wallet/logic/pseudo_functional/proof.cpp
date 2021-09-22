
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



#include "wallet/api/wallet_errors.h"
#include "wallet/logic/functional/proof.hpp"

#include "tools/common/base58.h"
#include "tools/epee/include/string_tools.h"


using namespace tools;

namespace wallet {
namespace logic {
namespace pseudo_functional {
namespace proof {

  const std::optional<std::vector<size_t>> verify_tx_proof
  (
   const cryptonote::transaction &tx
   , const cryptonote::account_public_address &address
   , const bool is_subaddress
   , const std::string &message
   , const std::string &sig_str
   ) {

    const std::string header = std::string(config::HASH_KEY_TX_PROOF_V4);

    const size_t header_len = header.size();
    THROW_WALLET_EXCEPTION_IF
      (
       sig_str.size() < header_len || sig_str.substr(0, header_len) != header
       , error::wallet_internal_error
       , "Signature header check error"
       );

    // decode base58
    std::vector<crypto::schnorr_signature> sig(1);
    const size_t sig_len = tools::base58::encode(epee::string_tools::blob_to_string(epee::pod_to_span(sig[0]))).size();

    const size_t num_sigs = (sig_str.size() - header_len) / sig_len;

    THROW_WALLET_EXCEPTION_IF
      (
       sig_str.size() != header_len + num_sigs * sig_len
       , error::wallet_internal_error
       , "Wrong signature size"
       );

    sig.resize(num_sigs);

    for (size_t i = 0; i < num_sigs; ++i)
    {
      std::string sig_decoded;
      const size_t offset = header_len + i * sig_len;

      THROW_WALLET_EXCEPTION_IF
        (
         !tools::base58::decode(sig_str.substr(offset, sig_len), sig_decoded)
         , error::wallet_internal_error
         , "Signature decoding error"
         );

      THROW_WALLET_EXCEPTION_IF
        (
         sizeof(crypto::schnorr_signature) != sig_decoded.size()
         , error::wallet_internal_error
         , "Signature decoding error"
         );

      constexpr size_t schnorr_size = sizeof(crypto::schnorr_signature);

      crypto::schnorr_signature_unnormalized sig_unsafe;

      memcpy(&sig_unsafe, sig_decoded.data(), schnorr_size);


      // reject invalid keys
      const auto maybeSig = maybe_valid_schnorr_signature(sig_unsafe);
      if (!maybeSig) return {};

      sig[i] = *maybeSig;
    }

    const crypto::hash txid = cryptonote::get_transaction_hash(tx);
    epee::blob::data prefix_data(txid.data.data(), txid.data.size());
    prefix_data += epee::string_tools::string_to_blob(message);
    crypto::hash prefix_hash = crypto::sha3(prefix_data);

    // check signature
    std::vector<int> good_signature(num_sigs, 0);

    const auto maybe_tx_output_pub_keys = get_all_tx_output_public_keys_from_extra(tx, tx.vout.size());
    if (!maybe_tx_output_pub_keys) return {};
    const auto tx_output_pub_keys = *maybe_tx_output_pub_keys;

    std::vector<size_t> found_indices;
    for (size_t i = 0; i < tx_output_pub_keys.size(); ++i)
    {
      const bool good_signature_for_tx_output_pub_key = is_subaddress
        ? crypto::verify_tx_proof
        (prefix_hash, tx_output_pub_keys[i], address.m_spend_public_key, sig[i])
        : crypto::verify_tx_proof
        (prefix_hash, tx_output_pub_keys[i], std::nullopt, sig[i]);

      if (good_signature_for_tx_output_pub_key) {
        found_indices.push_back(i);
      }
      else {
        LOG_WARNING("bad signature for tx output pub key at index: " << i);
      }
    }

    // received = wallet::logic::functional::proof::get_tx_key_received_helper
    //   (tx, {}, tx_output_shared_secrets, address);

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
