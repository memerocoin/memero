
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
   )
  {
    const crypto::hash txid = cryptonote::get_transaction_hash(tx);
    epee::blob::data prefix_data(txid.data.data(), txid.data.size());
    prefix_data += epee::string_tools::string_to_blob(message);
    crypto::hash prefix_hash= crypto::sha3(prefix_data);

    std::vector<crypto::public_key> shared_secret;
    std::vector<crypto::schnorr_signature> sig;
    std::string sig_str = std::string(config::HASH_KEY_TX_PROOF_V4);

    if (output_secret_keys.empty()) {
      THROW_WALLET_EXCEPTION_IF(!tx_key, tools::error::wallet_internal_error, "Tx pubkey was not found");
      const auto ss = crypto::p2pk(address.m_view_public_key ^ (*tx_key));
      shared_secret.push_back(ss);

      crypto::public_key tx_pub_key;
      if (is_subaddress)
      {
        tx_pub_key = crypto::p2pk(address.m_spend_public_key ^ (*tx_key));
        sig.push_back
          (crypto::generate_tx_proof
            (prefix_hash, tx_pub_key, address.m_spend_public_key, *tx_key));
      }

      else
      {
        tx_pub_key = to_pk(*tx_key);
        sig.push_back
          (
            crypto::generate_tx_proof
            (prefix_hash, tx_pub_key, std::nullopt, *tx_key));
      }
    }
    else {
      for (size_t i = 0; i < output_secret_keys.size(); ++i)
      {
        auto const output_ss = crypto::p2pk
        (address.m_view_public_key ^ output_secret_keys[i]);

        shared_secret.push_back(output_ss);

        crypto::public_key tx_output_pub_key;

        if (is_subaddress)
        {
          tx_output_pub_key = crypto::p2pk(address.m_spend_public_key ^ output_secret_keys[i]);
          sig.push_back
            (crypto::generate_tx_proof
            (prefix_hash, tx_output_pub_key, address.m_spend_public_key, output_secret_keys[i]));
        }
        else
        {
          tx_output_pub_key = to_pk(output_secret_keys[i]);
          sig.push_back
            (crypto::generate_tx_proof
            (prefix_hash, tx_output_pub_key, std::nullopt, output_secret_keys[i]));
        }
      }
    }

    // check if this address actually received any funds

    std::map<size_t, crypto::tx_output_ecdh_shared_secret> tx_output_shared_secrets;

    for (size_t i = 0; i < shared_secret.size(); i++) {
      const auto tx_output_shared_secret =
        crypto::derive_tx_output_ecdh_shared_secret(shared_secret[i], crypto::s2sk(rct::s_one));

      tx_output_shared_secrets[i] = tx_output_shared_secret;
    };

    std::vector<std::string> sig_str_v;
    std::transform
      (
       sig.begin()
       , sig.end()
       , std::back_inserter(sig_str_v)
       , [](const auto& s) {
         return tools::base58::encode(epee::string_tools::blob_to_string(epee::pod_to_span(s)));
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
      (tx, {}, tx_output_shared_secrets, address);

    THROW_WALLET_EXCEPTION_IF(!received, tools::error::wallet_internal_error, "No funds received in this tx.");

    return sig_str_final;
  }

} // proof
} // controller
} // logic
} // wallet
