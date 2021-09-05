
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


using namespace tools;

namespace wallet {
namespace logic {
namespace controller {
namespace proof {

  const std::string get_tx_proof
  (
   const cryptonote::transaction &tx
   , const crypto::secret_key &tx_key
   , const std::vector<crypto::secret_key> &additional_tx_keys
   , const cryptonote::account_public_address &address
   , const bool is_subaddress
   , const std::string &message
   , const std::optional<crypto::secret_key> view_secret_key
   )
  {
    // determine if the address is found in the subaddress hash table (i.e. whether the proof is outbound or inbound)

    // const bool is_out = m_subaddresses.count(address.m_spend_public_key) == 0;

    const crypto::hash txid = cryptonote::get_transaction_hash(tx);
    epee::blob::data prefix_data(txid.data.data(), txid.data.size());
    prefix_data += epee::string_tools::string_to_blob(message);
    crypto::hash prefix_hash= crypto::sha3(prefix_data);

    std::vector<crypto::public_key> shared_secret;
    std::vector<crypto::double_schnorr_signature> sig;
    std::string sig_str;

    if (!view_secret_key)
    {
      const size_t num_sigs = 1 + additional_tx_keys.size();
      shared_secret.resize(num_sigs);
      sig.resize(num_sigs);

      shared_secret[0] = rct::rct_p2pk
        (rct::multP(rct::pk2rct_p(address.m_view_public_key), rct::sk2rct_s(tx_key)));
      crypto::public_key tx_pub_key;
      if (is_subaddress)
      {
        tx_pub_key = rct_p2pk
          (rct::multP(rct::pk2rct_p(address.m_spend_public_key), rct::sk2rct_s(tx_key)));
        sig[0] = crypto::generate_tx_proof(prefix_hash, tx_pub_key, address.m_view_public_key, address.m_spend_public_key, shared_secret[0], tx_key);
      }
      else
      {
        tx_pub_key = to_pk(tx_key);
        sig[0] = crypto::generate_tx_proof(prefix_hash, tx_pub_key, address.m_view_public_key, std::nullopt, shared_secret[0], tx_key);
      }
      for (size_t i = 1; i < num_sigs; ++i)
      {
        shared_secret[i] = rct::rct_p2pk
          (rct::multP(rct::pk2rct_p(address.m_view_public_key), rct::sk2rct_s(additional_tx_keys[i - 1])));
        if (is_subaddress)
        {
          tx_pub_key = rct_p2pk
            (rct::multP(rct::pk2rct_p(address.m_spend_public_key), rct::sk2rct_s(additional_tx_keys[i - 1])));
          sig[i] = crypto::generate_tx_proof(prefix_hash, tx_pub_key, address.m_view_public_key, address.m_spend_public_key, shared_secret[i], additional_tx_keys[i - 1]);
        }
        else
        {
          tx_pub_key = to_pk(additional_tx_keys[i - 1]);
          sig[i] = crypto::generate_tx_proof(prefix_hash, tx_pub_key, address.m_view_public_key, std::nullopt, shared_secret[i], additional_tx_keys[i - 1]);
        }
      }
      sig_str = std::string("OutProofV2");
    }
    else
    {
      crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
      THROW_WALLET_EXCEPTION_IF(tx_pub_key == crypto::null_pkey, tools::error::wallet_internal_error, "Tx pubkey was not found");

      std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(tx);
      const size_t num_sigs = 1 + additional_tx_pub_keys.size();
      shared_secret.resize(num_sigs);
      sig.resize(num_sigs);

      const crypto::secret_key& a = view_secret_key.value();
      shared_secret[0] =  rct_p2pk
        (rct::multP(rct::pk2rct_p(tx_pub_key), rct::sk2rct_s(a)));
      if (is_subaddress)
      {
        sig[0] = crypto::generate_tx_proof(prefix_hash, address.m_view_public_key, tx_pub_key, address.m_spend_public_key, shared_secret[0], a);
      }
      else
      {
        sig[0] = crypto::generate_tx_proof(prefix_hash, address.m_view_public_key, tx_pub_key, std::nullopt, shared_secret[0], a);
      }
      for (size_t i = 1; i < num_sigs; ++i)
      {
        shared_secret[i] = rct_p2pk
          (rct::multP(rct::pk2rct_p(additional_tx_pub_keys[i - 1]), rct::sk2rct_s(a)));
        if (is_subaddress)
        {
          sig[i] = crypto::generate_tx_proof(prefix_hash, address.m_view_public_key, additional_tx_pub_keys[i - 1], address.m_spend_public_key, shared_secret[i], a);
        }
        else
        {
          sig[i] = crypto::generate_tx_proof(prefix_hash, address.m_view_public_key, additional_tx_pub_keys[i - 1], std::nullopt, shared_secret[i], a);
        }
      }
      sig_str = std::string("InProofV2");
    }

    const size_t num_sigs = shared_secret.size();

    // check if this address actually received any funds
    const std::optional<crypto::tx_ecdh_shared_secret> derivation =
      crypto::derive_tx_ecdh_shared_secret(shared_secret[0], crypto::s2sk(rct::s_one));
    THROW_WALLET_EXCEPTION_IF(!derivation
       , tools::error::wallet_internal_error, "Failed to generate key derivation");

    std::vector<crypto::tx_ecdh_shared_secret> tx_shared_secrets(num_sigs - 1);
    for (size_t i = 1; i < num_sigs; ++i) {
      const std::optional<crypto::tx_ecdh_shared_secret> additional_tx_shared_secret =
        crypto::derive_tx_ecdh_shared_secret(shared_secret[i], crypto::s2sk(rct::s_one));
      THROW_WALLET_EXCEPTION_IF
        ( !additional_tx_shared_secret
         , tools::error::wallet_internal_error, "Failed to generate key derivation");
      tx_shared_secrets[i - 1] = *additional_tx_shared_secret;
    }

    uint64_t received = wallet::logic::functional::proof::get_tx_key_received_helper
      (tx, *derivation, tx_shared_secrets, address);
    THROW_WALLET_EXCEPTION_IF(!received, tools::error::wallet_internal_error, "No funds received in this tx.");

    // concatenate all signature strings
    for (size_t i = 0; i < num_sigs; ++i)
      sig_str +=
        tools::base58::encode(epee::string_tools::blob_to_string(shared_secret[i].data)) +
        tools::base58::encode(epee::string_tools::blob_to_string(epee::pod_to_span(sig[i])));
    return sig_str;
  }

} // proof
} // controller
} // logic
} // wallet
