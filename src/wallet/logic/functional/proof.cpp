
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


using namespace tools;

namespace wallet {
namespace logic {
namespace functional {
namespace proof {

  const uint64_t get_tx_key_received_helper
  (
   const cryptonote::transaction &tx
   , const std::optional<crypto::tx_ecdh_shared_secret> &tx_shared_secret
   , const std::map<size_t, crypto::tx_ecdh_shared_secret> &tx_shared_secrets
   , const cryptonote::account_public_address &address
   )
  {
    uint64_t received = 0;

    for (size_t n = 0; n < tx.vout.size(); ++n)
    {
      const cryptonote::txout_to_key* const tx_output = boost::get<cryptonote::txout_to_key>(std::addressof(tx.vout[n].target));
      if (!tx_output)
        continue;

      bool found = false;
      crypto::tx_ecdh_shared_secret found_shared_secret = {};

      if (tx_shared_secret) {
        const std::optional<crypto::public_key> maybe_derived_tx_output_public_key =
          crypto::derive_tx_output_public_key_from_spend_public_key(*tx_shared_secret, n, address.m_spend_public_key);

        THROW_WALLET_EXCEPTION_IF(!maybe_derived_tx_output_public_key, error::wallet_internal_error, "Failed to derive public key");

        found = tx_output->key == *maybe_derived_tx_output_public_key;
        found_shared_secret = *tx_shared_secret;
      }

      if (!found && tx_shared_secrets.contains(n))
      {
        const auto maybe_derived_tx_output_public_key_1 =
          crypto::derive_tx_output_public_key_from_spend_public_key(tx_shared_secrets.at(n), n, address.m_spend_public_key);
        THROW_WALLET_EXCEPTION_IF(!maybe_derived_tx_output_public_key_1, error::wallet_internal_error, "Failed to derive public key");

        found = tx_output->key == *maybe_derived_tx_output_public_key_1;
        found_shared_secret = tx_shared_secrets.at(n);
      }

      if (found)
      {
        uint64_t amount;
        if (tx.ringct_essential.type == rct::RCTTypeNull)
        {
          amount = tx.vout[n].amount;
        }
        else
        {
          const rct::rct_scalar ecdh_derived_secret =
            rct::s2s(crypto::hash_tx_shared_secret_to_scalar(found_shared_secret, n));

          const crypto::ec_scalar_unnormalized blinding_factor =
            get_blinding_factor_from_ecdh_shared_secret(ecdh_derived_secret);

          THROW_WALLET_EXCEPTION_IF
            (
             crypto::is_not_reduced(blinding_factor)
             , error::wallet_internal_error
             , "Bad ECDH input blinding_factor"
             );

          const crypto::ec_scalar_unnormalized masked_amount = tx.ringct_essential.ecdh[n].masked_amount;
          const crypto::ec_scalar_unnormalized amount_unnormalized =
            crypto::d2s(rct::decode_by_ecdh_shared_secret(masked_amount, ecdh_derived_secret));

          THROW_WALLET_EXCEPTION_IF
            (
             crypto::is_not_reduced(amount_unnormalized)
             , error::wallet_internal_error
             , "Bad ECDH input amount"
             );

          const rct::rct_point C = tx.ringct_essential.outPk[n].amount_commit;

          const auto ecdh_amount = scalar_to_int(rct::s2s(crypto::reduce(amount_unnormalized)));
          const rct::rct_point C_check = rct::commit(blinding_factor, ecdh_amount);

          if (C == C_check)
            amount = ecdh_amount;
          else
            amount = 0;
        }

        received += amount;
      }
    }
    return received;
  }

} // proof
} // functional
} // logic
} // wallet
