// Copyright (c) 2021, The Lolnero Project
// Copyright (c) 2016, Monero Research Labs
//
// Author: Shen Noether <shen.noether@gmx.com>
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

#include "clsag.hpp"

#include "tools/epee/include/logging.hpp"

#include "math/ringct/functional/curveConstants.hpp"
#include "math/ringct/functional/rctOps.hpp"

#include "math/crypto/controller/keyGen.hpp"

#include "config/cryptonote.hpp"


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

namespace rct {
  bool verify_clsag_signature
  (
    const crypto::hash message
    , const clsag sig
    , const output_public_dataS decoys
    , const rct_point pseudo_input_commit
    )
  {
    const size_t n = decoys.size();

    // Check data
    LOG_ERROR_AND_RETURN_UNLESS(n >= 1, false, "Empty decoys");
    LOG_ERROR_AND_RETURN_UNLESS(n == sig.s.size(), false, "sig.s vector is the wrong size!");

    // Aggregation hashes
    crypto::dataV mu_P_to_hash = {{}};
    std::transform
      (
        decoys.begin()
        , decoys.end()
        , std::back_inserter(mu_P_to_hash)
        , [](const auto& x) { return x.output_spend_pk; }
        );

    std::transform
      (
        decoys.begin()
        , decoys.end()
        , std::back_inserter(mu_P_to_hash)
        , [](const auto& x) { return x.commit; }
        );

    mu_P_to_hash.push_back(sig.signer_pk_image);
    mu_P_to_hash.push_back(sig.signer_pk_image_from_blinding_factor_surplus);
    mu_P_to_hash.push_back(pseudo_input_commit);

    crypto::dataV mu_C_to_hash = mu_P_to_hash;

    std::copy_n
      (
        config::HASH_KEY_CLSAG_AGG_0.data()
        , config::HASH_KEY_CLSAG_AGG_0.size()
        , mu_P_to_hash[0].data.begin()
        );

    std::copy_n
      (
        config::HASH_KEY_CLSAG_AGG_1.data()
        , config::HASH_KEY_CLSAG_AGG_1.size()
        , mu_C_to_hash[0].data.begin()
        );

    const rct_scalar mu_P = hash_dataV_to_scalar(mu_P_to_hash);
    const rct_scalar mu_C = hash_dataV_to_scalar(mu_C_to_hash);

    // Set up round hash
    crypto::dataV c_to_hash = {{}}; // domain, P, C, pseudo_input_commit, message, L, R
    std::copy_n
      (
        config::HASH_KEY_CLSAG_ROUND.data()
        , config::HASH_KEY_CLSAG_ROUND.size()
        , c_to_hash[0].data.begin()
        );

    std::transform
      (
        decoys.begin()
        , decoys.end()
        , std::back_inserter(c_to_hash)
        , [](const auto& x) { return x.output_spend_pk; }
        );

    std::transform
      (
        decoys.begin()
        , decoys.end()
        , std::back_inserter(c_to_hash)
        , [](const auto& x) { return x.commit; }
        );

    c_to_hash.push_back(pseudo_input_commit);
    c_to_hash.push_back(crypto::h2d(message));
    c_to_hash.push_back({}); // reserve for L
    c_to_hash.push_back({}); // reserve for R


    const rct_scalar c1 = sig.c1;

    rct_scalar c = c1;
    size_t i = 0;

    while (i < n) {
      const rct_scalar c_p = mu_P * c;
      const rct_scalar c_c = mu_C * c;

      const rct_point decoy_commit = decoys[i].commit;

      const rct_point decoy_commit_surplus = decoy_commit - pseudo_input_commit;

      // Compute L
      const rct_point L = sum
        (
          std::array
          {
            G_(sig.s[i])
            , decoys[i].output_spend_pk ^ c_p
            , decoy_commit_surplus ^ c_c
          }
          );

      // Compute R
      const rct_point k = crypto::hash_to_point_via_field(decoys[i].output_spend_pk);

      const rct_point R = sum
        (
          std::array
          {
            k ^ sig.s[i]
            , sig.signer_pk_image ^ c_p
            , sig.signer_pk_image_from_blinding_factor_surplus ^ (c_c * s_eight)
          }
          );

      c_to_hash[2*n+3] = L;
      c_to_hash[2*n+4] = R;

      c = hash_dataV_to_scalar(c_to_hash);
      LOG_ERROR_AND_RETURN_IF((c == rct::s_zero), false, "Bad signature hash");

      i++;
    }

    return c == c1;
  }

}
