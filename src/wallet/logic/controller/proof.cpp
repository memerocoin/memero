
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
   , const std::optional<crypto::secret_key> &tx_key
   , const std::vector<crypto::secret_key> &output_secret_keys
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
      LOG_FATAL("get tx proof Out is unsupported");

      if (tx_key) {
        const auto ss = rct::rct_p2pk
         (rct::multP(rct::pk2rct_p(address.m_view_public_key), rct::sk2rct_s(*tx_key)));

        shared_secret.push_back(ss);

        crypto::public_key tx_pub_key;
        if (is_subaddress)
        {
          tx_pub_key = rct_p2pk
            (rct::multP(rct::pk2rct_p(address.m_spend_public_key), rct::sk2rct_s(*tx_key)));
          sig.push_back
            (crypto::generate_tx_proof
             (prefix_hash, tx_pub_key, address.m_view_public_key, address.m_spend_public_key, ss, *tx_key));
        }

        else
        {
          tx_pub_key = to_pk(*tx_key);
          sig.push_back
            (
             crypto::generate_tx_proof
             (prefix_hash, tx_pub_key, address.m_view_public_key, std::nullopt, ss, *tx_key));
        }
      }

      for (size_t i = 0; i < output_secret_keys.size(); ++i)
      {
        auto const output_ss = rct::rct_p2pk
         (rct::multP(rct::pk2rct_p(address.m_view_public_key), rct::sk2rct_s(output_secret_keys[i])));

        shared_secret.push_back(output_ss);

        crypto::public_key tx_output_pub_key;

        if (is_subaddress)
        {
          tx_output_pub_key = rct_p2pk
            (rct::multP(rct::pk2rct_p(address.m_spend_public_key), rct::sk2rct_s(output_secret_keys[i])));
          sig.push_back
            (crypto::generate_tx_proof
             (prefix_hash, tx_output_pub_key, address.m_view_public_key
              , address.m_spend_public_key, output_ss, output_secret_keys[i]));
        }
        else
        {
          tx_output_pub_key = to_pk(output_secret_keys[i]);
          sig.push_back
            (crypto::generate_tx_proof
             (prefix_hash, tx_output_pub_key, address.m_view_public_key, std::nullopt, output_ss, output_secret_keys[i]));
        }
      }
      sig_str = std::string("OutProofV2");
    }
    else
    {
      const auto tx_pub_keys = get_tx_pub_keys_from_extra(tx);
      // THROW_WALLET_EXCEPTION_IF(!tx_pub_key, tools::error::wallet_internal_error, "Tx pubkey was not found");

      const auto num_sigs = tx_pub_keys.size();

      shared_secret.resize(num_sigs);
      sig.resize(num_sigs);

      const crypto::secret_key& a = view_secret_key.value();

      for (size_t i = 0; i < num_sigs; ++i)
      {
        shared_secret[i] = rct_p2pk
          (rct::multP(rct::pk2rct_p(tx_pub_keys[i]), rct::sk2rct_s(a)));
        if (is_subaddress)
        {
          sig[i] = crypto::generate_tx_proof(prefix_hash, address.m_view_public_key, tx_pub_keys[i], address.m_spend_public_key, shared_secret[i], a);
        }
        else
        {
          sig[i] = crypto::generate_tx_proof(prefix_hash, address.m_view_public_key, tx_pub_keys[i], std::nullopt, shared_secret[i], a);
        }
      }
      sig_str = std::string("InProofV2");
    }

    // check if this address actually received any funds

    const auto tx_pub_key = get_tx_pub_key_from_extra(tx);

    std::optional<crypto::tx_ecdh_shared_secret> tx_shared_secret;

    if (tx_pub_key) {
      tx_shared_secret =
      crypto::derive_tx_ecdh_shared_secret(shared_secret.front(), crypto::s2sk(rct::s_one));

      THROW_WALLET_EXCEPTION_IF
      (!tx_shared_secret
       , tools::error::wallet_internal_error, "Failed to generate key tx_shared_secret");

      sig_str +=
        tools::base58::encode(epee::string_tools::blob_to_string(shared_secret.front().data)) +
        tools::base58::encode(epee::string_tools::blob_to_string(epee::pod_to_span(sig.front())));

      shared_secret.erase(shared_secret.begin());
      sig.erase(sig.begin());
    }


    std::map<size_t, crypto::tx_ecdh_shared_secret> tx_shared_secrets;
    for (size_t i = 0; i < shared_secret.size(); i++) {
      const std::optional<crypto::tx_ecdh_shared_secret> tx_output_shared_secret =
        crypto::derive_tx_ecdh_shared_secret(shared_secret[i], crypto::s2sk(rct::s_one));

      THROW_WALLET_EXCEPTION_IF
        ( !tx_output_shared_secret
          , tools::error::wallet_internal_error, "Failed to generate key tx_shared_secret");

      tx_shared_secrets[i] = *tx_output_shared_secret;
    };

    std::vector<std::string> sig_str_v;
    std::transform
      (
       shared_secret.begin()
       , shared_secret.end()
       , sig.begin()
       , std::back_inserter(sig_str_v)
       , [](const auto& secret, const auto& s) {
         return tools::base58::encode(epee::string_tools::blob_to_string(secret.data))
           + tools::base58::encode(epee::string_tools::blob_to_string(epee::pod_to_span(s)));
       }
       );

    // concatenate all signature strings
    const std::string sig_str_final = std::reduce
      (
       sig_str_v.begin()
       , sig_str_v.end()
       , sig_str
       );

    uint64_t received = wallet::logic::functional::proof::get_tx_key_received_helper
      (tx, tx_shared_secret, tx_shared_secrets, address);

    THROW_WALLET_EXCEPTION_IF(!received, tools::error::wallet_internal_error, "No funds received in this tx.");

    return sig_str_final;
  }

} // proof
} // controller
} // logic
} // wallet
