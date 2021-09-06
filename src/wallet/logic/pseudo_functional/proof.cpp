
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

  const bool verify_tx_proof
  (
   const cryptonote::transaction &tx
   , const cryptonote::account_public_address &address
   , const bool is_subaddress
   , const std::string &message
   , const std::string &sig_str
   , uint64_t &received
   ) {

    // InProofV1, InProofV2, OutProofV1, OutProofV2
    const bool is_out = sig_str.substr(0, 3) == "Out";
    const std::string header = is_out ? sig_str.substr(0,10) : sig_str.substr(0,9);

    const size_t header_len = header.size();
    THROW_WALLET_EXCEPTION_IF(sig_str.size() < header_len || sig_str.substr(0, header_len) != header, error::wallet_internal_error,
      "Signature header check error");

    // decode base58
    std::vector<crypto::public_key> shared_secret(1);
    std::vector<crypto::double_schnorr_signature> sig(1);

    const size_t pk_len = tools::base58::encode(epee::string_tools::blob_to_string(shared_secret[0].data)).size();
    const size_t sig_len = tools::base58::encode(epee::string_tools::blob_to_string(epee::pod_to_span(sig[0]))).size();

    const size_t num_sigs = (sig_str.size() - header_len) / (pk_len + sig_len);

    THROW_WALLET_EXCEPTION_IF
      (
       sig_str.size() != header_len + num_sigs * (pk_len + sig_len)
       , error::wallet_internal_error
       , "Wrong signature size"
       );

    shared_secret.resize(num_sigs);
    sig.resize(num_sigs);

    for (size_t i = 0; i < num_sigs; ++i)
    {
      std::string pk_decoded;
      std::string sig_decoded;
      const size_t offset = header_len + i * (pk_len + sig_len);

      THROW_WALLET_EXCEPTION_IF
        (
         !tools::base58::decode(sig_str.substr(offset, pk_len), pk_decoded)
         , error::wallet_internal_error
         , "Signature decoding error"
         );

      THROW_WALLET_EXCEPTION_IF
        (
         !tools::base58::decode(sig_str.substr(offset + pk_len, sig_len), sig_decoded)
         , error::wallet_internal_error
         , "Signature decoding error"
         );

      THROW_WALLET_EXCEPTION_IF
        (
         sizeof(crypto::public_key) != pk_decoded.size() || sizeof(crypto::double_schnorr_signature) != sig_decoded.size()
         , error::wallet_internal_error
         , "Signature decoding error"
         );

      memcpy(&shared_secret[i], pk_decoded.data(), sizeof(crypto::public_key));

      constexpr size_t schnorr_size = sizeof(crypto::schnorr_signature);

      crypto::schnorr_signature_unnormalized sig_unsafe_1;
      crypto::schnorr_signature_unnormalized sig_unsafe_2;

      memcpy(&sig_unsafe_1, sig_decoded.data(), schnorr_size);
      memcpy(&sig_unsafe_2, sig_decoded.data() + schnorr_size, schnorr_size);

      sig[i].first = reduce_schnorr(sig_unsafe_1);
      sig[i].second = reduce_schnorr(sig_unsafe_2);
    }

    const auto tx_pub_key = get_tx_pub_key_from_extra(tx);

    std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(tx);

    const auto expected_sigs = tx_pub_key ? additional_tx_pub_keys.size() + 1 : additional_tx_pub_keys.size();
    THROW_WALLET_EXCEPTION_IF(expected_sigs != num_sigs, error::wallet_internal_error, "Signature size mismatch with additional tx pubkeys");

    const crypto::hash txid = cryptonote::get_transaction_hash(tx);
    epee::blob::data prefix_data(txid.data.data(), txid.data.size());
    prefix_data += epee::string_tools::string_to_blob(message);
    crypto::hash prefix_hash = crypto::sha3(prefix_data);

    // check signature
    std::vector<int> good_signature(num_sigs, 0);
    if (is_out)
    {
      good_signature[0] = !tx_pub_key ? false
        : is_subaddress ?
        crypto::verify_tx_proof(prefix_hash, *tx_pub_key, address.m_view_public_key, address.m_spend_public_key, shared_secret[0], sig[0]) :
        crypto::verify_tx_proof(prefix_hash, *tx_pub_key, address.m_view_public_key, std::nullopt, shared_secret[0], sig[0]);

      for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
      {
        good_signature[i + 1] = is_subaddress ?
          crypto::verify_tx_proof(prefix_hash, additional_tx_pub_keys[i], address.m_view_public_key, address.m_spend_public_key, shared_secret[i + 1], sig[i + 1]) :
          crypto::verify_tx_proof(prefix_hash, additional_tx_pub_keys[i], address.m_view_public_key, std::nullopt, shared_secret[i + 1], sig[i + 1]);
      }
    }
    else
    {
      good_signature[0] = !tx_pub_key ? false
        : is_subaddress ?
        crypto::verify_tx_proof(prefix_hash, address.m_view_public_key, *tx_pub_key, address.m_spend_public_key, shared_secret[0], sig[0]) :
        crypto::verify_tx_proof(prefix_hash, address.m_view_public_key, *tx_pub_key, std::nullopt, shared_secret[0], sig[0]);

      for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
      {
        good_signature[i + 1] = is_subaddress ?
          crypto::verify_tx_proof(prefix_hash, address.m_view_public_key, additional_tx_pub_keys[i], address.m_spend_public_key, shared_secret[i + 1], sig[i + 1]) :
          crypto::verify_tx_proof(prefix_hash, address.m_view_public_key, additional_tx_pub_keys[i], std::nullopt, shared_secret[i + 1], sig[i + 1]);
      }
    }

    if (std::any_of(good_signature.begin(), good_signature.end(), [](int i) { return i > 0; }))
    {
      // non empty optional with default value
      std::optional<crypto::tx_ecdh_shared_secret> tx_shared_secret;

      if (good_signature[0]) {
        // obtain key derivation by multiplying rct_scalar 1 to the shared secret
          tx_shared_secret = crypto::derive_tx_ecdh_shared_secret(shared_secret[0], crypto::s2sk(rct::s_one));
          THROW_WALLET_EXCEPTION_IF
          ( !tx_shared_secret
            , error::wallet_internal_error, "Failed to generate key derivation");
      }

      std::vector<crypto::tx_ecdh_shared_secret> tx_shared_secrets(num_sigs - 1);

      for (size_t i = 1; i < num_sigs; ++i) {
        if (good_signature[i]) {
          const std::optional<crypto::tx_ecdh_shared_secret> additional_tx_shared_secret =
            crypto::derive_tx_ecdh_shared_secret(shared_secret[i], crypto::s2sk(rct::s_one));
          THROW_WALLET_EXCEPTION_IF
            ( !additional_tx_shared_secret
             , error::wallet_internal_error, "Failed to generate key derivation");
          tx_shared_secrets[i-1] = *additional_tx_shared_secret;
        }
      }

      received = wallet::logic::functional::proof::get_tx_key_received_helper
        (tx, *tx_shared_secret, tx_shared_secrets, address);
      return true;
    }
    return false;
  }


} // proof
} // pseudo_functional
} // logic
} // wallet
