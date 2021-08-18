
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
   , const crypto::key_derivation &derivation
   , const std::vector<crypto::key_derivation> &additional_derivations
   , const cryptonote::account_public_address &address
   )
  {
    uint64_t received = 0;

    for (size_t n = 0; n < tx.vout.size(); ++n)
    {
      const cryptonote::txout_to_key* const out_key = boost::get<cryptonote::txout_to_key>(std::addressof(tx.vout[n].target));
      if (!out_key)
        continue;

      crypto::public_key derived_out_key;
      bool r = crypto::derive_public_key(derivation, n, address.m_spend_public_key, derived_out_key);
      THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to derive public key");
      bool found = out_key->key == derived_out_key;
      crypto::key_derivation found_derivation = derivation;
      if (!found && !additional_derivations.empty())
      {
        r = crypto::derive_public_key(additional_derivations[n], n, address.m_spend_public_key, derived_out_key);
        THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to derive public key");
        found = out_key->key == derived_out_key;
        found_derivation = additional_derivations[n];
      }

      if (found)
      {
        uint64_t amount;
        if (tx.rct_signatures.type == rct::RCTTypeNull)
        {
          amount = tx.vout[n].amount;
        }
        else
        {
          const rct::rct_scalar scalar1 = rct::s2s(crypto::hash_derivation_to_scalar(found_derivation, n));
          const crypto::ec_scalar_unnormalized ecdh_amount_raw = tx.rct_signatures.ecdhInfo[n].amount;
          const rct::ecdhTuple ecdh_info = rct::ecdhDecode(ecdh_amount_raw, scalar1);
          const rct::rct_point C = tx.rct_signatures.outPk[n].commit_of_amount;

          THROW_WALLET_EXCEPTION_IF(crypto::is_not_reduced(ecdh_info.mask), error::wallet_internal_error, "Bad ECDH input mask");
          THROW_WALLET_EXCEPTION_IF(crypto::is_not_reduced(ecdh_info.amount), error::wallet_internal_error, "Bad ECDH input amount");

          const rct::rct_scalar ecdh_amount = rct::s2s(crypto::reduce(ecdh_info.amount));
          const rct::rct_point Ctmp = rct::addMultG_H(ecdh_info.mask, ecdh_amount);
          if (C == Ctmp)
            amount = rct::scalar_to_int(ecdh_amount);
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
