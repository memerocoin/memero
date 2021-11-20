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

#include "clsagGen.hpp"

#include "tools/epee/include/logging.hpp"

#include "math/ringct/functional/curveConstants.hpp"
#include "math/ringct/functional/rctOps.hpp"

#include "math/crypto/controller/keyGen.hpp"

#include "config/cryptonote.hpp"


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

namespace rct {


  // Generate a CLSAG signature
  // See paper by Goodell et al. (https://eprint.iacr.org/2019/654)
  //
  // The keys are set as follows:
  //   P[l] == p*G
  //   C[l] == z*G
  //   C[i] == C_nonzero[i] - C_offset (for hashing purposes) for all i
  clsag generate_clsag_signature_internal
  (
    const crypto::hash message
    , const rct_scalar signer_sk
    , const rct_scalar signer_blinding_factor_surplus
    , const size_t index_in_decoys
    , const rct_point pseudo_input_commit
    , const rct_pointV decoy_spend_pks
    , const rct_pointV decoy_commit_surplus
    , const rct_pointV decoy_commits
    )
  {
    size_t n = decoy_spend_pks.size(); // ring size
    LOG_ERROR_AND_THROW_UNLESS
      (
       n == decoy_commit_surplus.size()
       , "Signing and commitment rct_point vector sizes must match!"
       );

    LOG_ERROR_AND_THROW_UNLESS
      (
       n == decoy_commits.size()
       , "Signing and commitment rct_point vector sizes must match!"
       );

    LOG_ERROR_AND_THROW_UNLESS(index_in_decoys < n, "Signing index out of range!");

    // mages images
    const rct_point signer_pk_hash = crypto::hash_to_point_via_field(decoy_spend_pks[index_in_decoys]);

    const rct_point sig_signer_pk_image = signer_pk_hash ^ signer_sk;
    const rct_point D = signer_pk_hash ^ signer_blinding_factor_surplus;

    // Offset key image
    const rct_point sig_signer_pk_image_from_blinding_factor_surplus = D ^ rct::s_inv_eight;

    crypto::dataV mu_P_to_hash = {{}};
    mu_P_to_hash.insert(mu_P_to_hash.end(), decoy_spend_pks.begin(), decoy_spend_pks.end());
    mu_P_to_hash.insert(mu_P_to_hash.end(), decoy_commits.begin(), decoy_commits.end());
    mu_P_to_hash.push_back(sig_signer_pk_image);
    mu_P_to_hash.push_back(sig_signer_pk_image_from_blinding_factor_surplus);
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

    // Initial commitment
    crypto::dataV c_to_hash = {{}};
    std::copy_n
      (
        config::HASH_KEY_CLSAG_ROUND.data()
        , config::HASH_KEY_CLSAG_ROUND.size()
        , c_to_hash[0].data.begin()
        );

    c_to_hash.insert(c_to_hash.end(), decoy_spend_pks.begin(), decoy_spend_pks.end());
    c_to_hash.insert(c_to_hash.end(), decoy_commits.begin(), decoy_commits.end());
    c_to_hash.push_back(pseudo_input_commit);
    c_to_hash.push_back(crypto::h2d(message));

    const rct_scalar a = crypto::randomScalar();
    c_to_hash.push_back(G_(a));
    c_to_hash.push_back(signer_pk_hash ^ a);


    rct_scalar c = rct::hash_dataV_to_scalar(c_to_hash);

    size_t i = (index_in_decoys + 1) % n;
    rct_scalar sig_c1;
    if (i == 0) {
      sig_c1 = c;
    }

    // Decoy indices
    rct_scalarV s(n);

    while (i != index_in_decoys) {
      // carried from last round
      const rct_scalar c_p = mu_P * c;
      const rct_scalar c_c = mu_C * c;

      const auto sk = crypto::randomScalar();

      // Compute L
      const rct_point L = sum
        (
         std::array
         {
           G_(sk)
           , decoy_spend_pks[i] ^ c_p
           , decoy_commit_surplus[i] ^ c_c
         }
         );

      // Compute R
      const rct_point A = crypto::hash_to_point_via_field(decoy_spend_pks[i]);
      const rct_point R = sum
        (
         std::array
         {
           A ^ sk
           , sig_signer_pk_image ^ c_p
           , D ^ c_c
         }
         );

      s[i] = sk;

      c_to_hash[2*n+3] = L;
      c_to_hash[2*n+4] = R;
      // need to be remembered
      c = rct::hash_dataV_to_scalar(c_to_hash);

      i = (i + 1) % n;
      if (i == 0) {
        sig_c1 = c;
      }
    }

    // Compute final scalar
    s[index_in_decoys] = a - c * (mu_C * signer_blinding_factor_surplus + mu_P * signer_sk);

    return {
      s
      , sig_c1
      , sig_signer_pk_image
      , sig_signer_pk_image_from_blinding_factor_surplus
      };
  }


  clsag generate_clsag_signature
  (
   const crypto::hash message
   , const rct_scalar signer_sk
   , const rct_scalar signer_blinding_factor
   , const size_t index_in_decoys
   , const rct_scalar pseudo_input_blinding_factor
   , const rct_point pseudo_input_commit
   , const output_public_dataV decoys
   )
  {
    LOG_ERROR_AND_THROW_IF(decoys.empty(), "Empty decoys");

    rct_pointV decoy_spend_pks;
    std::transform
      (
        decoys.begin()
        , decoys.end()
        , std::back_inserter(decoy_spend_pks)
        , [](const auto& x) { return x.output_spend_pk; }
        );

    rct_pointV decoy_commits;
    std::transform
      (
        decoys.begin()
        , decoys.end()
        , std::back_inserter(decoy_commits)
        , [](const auto& x) { return x.commit; }
        );

    rct_pointV decoy_commit_surplus;
    std::transform
      (
        decoys.begin()
        , decoys.end()
        , std::back_inserter(decoy_commit_surplus)
        , [pseudo_input_commit](const auto& x) { return x.commit - pseudo_input_commit; }
        );

    const rct_scalar signer_blinding_factor_surplus = signer_blinding_factor - pseudo_input_blinding_factor;
    return generate_clsag_signature_internal
      (
       message
       , signer_sk
       , signer_blinding_factor_surplus
       , index_in_decoys
       , pseudo_input_commit
       , decoy_spend_pks
       , decoy_commit_surplus
       , decoy_commits
       );
  }

}
