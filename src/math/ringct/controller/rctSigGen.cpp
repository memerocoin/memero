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

#include "rctSigGen.hpp"

#include "math/ringct/functional/curveConstants.hpp"
#include "math/ringct/pseudo_functional/bulletproofs.hpp"

#include "cryptonote/basic/cryptonote_format_utils.h"

#include "tools/common/threadpool.h"
#include "tools/epee/include/logging.hpp"

#include "cryptonote/basic/functional/subaddress.hpp"


#include "config/cryptonote.hpp"

using namespace std;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

namespace rct {

  std::tuple<rct_scalarV, Bulletproof> generate_range_proof
  (
   const std::span<const rctOutputData> outputs
   )
  {
    std::vector<std::pair<const uint64_t, const rct_scalar>> xs;
    std::transform
      (
       outputs.begin()
       , outputs.end()
       , std::back_inserter(xs)
       , [](const auto& x) -> std::pair<uint64_t, rct_scalar> {
         return {x.amount, rct::get_blinding_factor_from_hashed_shared_secret(x.ecdh_shared_secret_hashed_by_index)};
       }
       );

    const Bulletproof proof = bulletproof_MAKE(xs);

    LOG_ERROR_AND_THROW_UNLESS(proof.V.size() == outputs.size(), "V does not have the expected size");

    rct_scalarV output_blinding_factors;
    std::transform
      (
       xs.begin()
       , xs.end()
       , std::back_inserter(output_blinding_factors)
       , [](const auto& x) { return x.second; }
       );

    return {output_blinding_factors, proof};
  }


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
    , const rct_pointV P
    , const rct_scalar p
    , const rct_pointV decoy_commit_differences
    , const rct_scalar z
    , const rct_pointV C_nonzero
    , const rct_point C_offset
    , const size_t index_in_decoys
    )
  {
    size_t n = P.size(); // ring size
    LOG_ERROR_AND_THROW_UNLESS
      (
       n == decoy_commit_differences.size()
       , "Signing and commitment rct_point vector sizes must match!"
       );

    LOG_ERROR_AND_THROW_UNLESS
      (
       n == C_nonzero.size()
       , "Signing and commitment rct_point vector sizes must match!"
       );

    LOG_ERROR_AND_THROW_UNLESS(index_in_decoys < n, "Signing index out of range!");

    // mages images
    const rct_point P_hash = hash_to_point_via_field(P[index_in_decoys]);

    const rct_scalar a = crypto::scalarGen();
    const rct_point sig_I = P_hash ^ p;
    const rct_point D = P_hash ^ z;

    // Offset key image
    const rct_point sig_D = D ^ rct::s_inv_eight;

    crypto::dataV mu_P_to_hash = {{}};
    mu_P_to_hash.insert(mu_P_to_hash.end(), P.begin(), P.end());
    mu_P_to_hash.insert(mu_P_to_hash.end(), C_nonzero.begin(), C_nonzero.end());
    mu_P_to_hash.push_back(sig_I);
    mu_P_to_hash.push_back(sig_D);
    mu_P_to_hash.push_back(C_offset);

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

    c_to_hash.insert(c_to_hash.end(), P.begin(), P.end());
    c_to_hash.insert(c_to_hash.end(), C_nonzero.begin(), C_nonzero.end());
    c_to_hash.push_back(C_offset);
    c_to_hash.push_back(crypto::h2d(message));
    c_to_hash.push_back(G_(a));
    c_to_hash.push_back(P_hash ^ a);


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

      const auto sk = crypto::scalarGen();

      // Compute L
      const rct_point L = sum
        (
         std::array
         {
           G_(sk)
           , P[i] ^ c_p
           , decoy_commit_differences[i] ^ c_c
         }
         );

      // Compute R
      const rct_point A = hash_to_point_via_field(P[i]);
      const rct_point R = sum
        (
         std::array
         {
           A ^ sk
           , sig_I ^ c_p
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
    s[index_in_decoys] = a - c * (mu_C * z + mu_P * p);

    return {
      s
      , sig_c1
      , sig_I
      , sig_D
      };
  }


  clsag generate_clsag_signature
  (
   const crypto::hash message
   , const output_public_dataV pubs
   , const rct_scalar input_spend_sk
   , const rct_scalar input_blinding_factor
   , const rct_scalar pseudo_blinding_factor
   , const rct_point pseudo_amount_commit
   , const size_t index_in_decoys
   )
  {
    LOG_ERROR_AND_THROW_IF(pubs.empty(), "Empty pubs");

    rct_pointV P;
    std::transform
      (
        pubs.begin()
        , pubs.end()
        , std::back_inserter(P)
        , [](const auto& x) { return x.output_spend_pk; }
        );

    rct_pointV C_nonzero;
    std::transform
      (
        pubs.begin()
        , pubs.end()
        , std::back_inserter(C_nonzero)
        , [](const auto& x) { return x.amount_commit; }
        );

    rct_pointV decoy_commit_differences;
    std::transform
      (
        pubs.begin()
        , pubs.end()
        , std::back_inserter(decoy_commit_differences)
        , [pseudo_amount_commit](const auto& x) { return x.amount_commit - pseudo_amount_commit; }
        );

    return generate_clsag_signature_internal
      (
       message
       , P
       , input_spend_sk
       , decoy_commit_differences
       , input_blinding_factor - pseudo_blinding_factor
       , C_nonzero
       , pseudo_amount_commit
       , index_in_decoys
       );
  }



  std::pair<rctData, rct_scalarV> generate_ringct
  (
   const crypto::hash message
   , const std::vector<rctInputData> inputs
   , const std::vector<rctOutputData> outputs
   , const amount_t fee
   )
  {
    LOG_ERROR_AND_THROW_UNLESS(inputs.size() > 0, "Empty inamounts");

    for (size_t n = 0; n < inputs.size(); ++n) {
      LOG_ERROR_AND_THROW_UNLESS(inputs[n].index_in_decoys < inputs[n].decoys.size(), "Bad index into decoys");
    }

    const auto [output_blinding_factors, proof] = generate_range_proof(outputs);

    std::vector<output_commit> outPk;
    std::transform
      (
       proof.V.begin()
       , proof.V.end()
       , std::back_inserter(outPk)
       , [](const auto& x) -> output_commit {
         return {crypto::mult8(x)};
       }
       );


    std::vector<ecdh_encrypted_data> ecdh;
    std::transform
      (
       outputs.begin(),
       outputs.end(),
       std::back_inserter(ecdh),
       [](const auto& x) -> ecdh_encrypted_data {
         return {encode_amount_by_ecdh_shared_secret(x.amount, x.ecdh_shared_secret_hashed_by_index)};
       }
       );


    rct_scalar output_blinding_factors_sum = std::reduce
      (
       output_blinding_factors.begin()
       , output_blinding_factors.end()
       , s_zero
       );


    // reserve the last one for generating a balanced pseudo sum
    rct_scalarV pseudo_blinding_factors(inputs.size() - 1);
    std::generate
      (
       pseudo_blinding_factors.begin()
       , pseudo_blinding_factors.end()
       , []() { return crypto::scalarGen(); }
       );

    rct_scalar pseudo_blinding_factors_sum =
      std::accumulate
      (
       pseudo_blinding_factors.begin()
       , pseudo_blinding_factors.end()
       , s_zero
       , std::plus<>()
       );

    rct_pointV pseudo_amount_commits;
    std::transform
      (
       pseudo_blinding_factors.begin()
       , pseudo_blinding_factors.end()
       , inputs.begin()
       , std::back_inserter(pseudo_amount_commits)
       , [](const auto& x, const auto& y) -> rct_point {
         return commit(y.amount, x);
       }
       );

    const auto pseudo_blinding_factor_difference = output_blinding_factors_sum - pseudo_blinding_factors_sum;
    pseudo_blinding_factors.push_back(pseudo_blinding_factor_difference);

    pseudo_amount_commits.push_back(commit(inputs.back().amount, pseudo_blinding_factor_difference));

    output_public_dataM decoys;

    std::transform
      (
       inputs.begin()
       , inputs.end()
       , std::back_inserter(decoys)
       , [](const auto x) -> output_public_dataV { return x.decoys; }
       );

    const rctData preRctSig =
      {
        RCTTypeCLSAG
        , message
        , decoys
        , ecdh
        , outPk
        , fee
        , {
          {toUnsafeBulletproof(proof)}
          , {}
          , pseudo_amount_commits
        }
      };

    const auto maybeMessage = get_ring_signature_message(preRctSig);
    LOG_ERROR_AND_THROW_UNLESS(maybeMessage, "failed to generate rct message");

    const crypto::hash full_message = *maybeMessage;
    std::vector<clsag_unsafe> clsags(inputs.size());
    std::generate
      (
       clsags.begin()
       , clsags.end()
       , [full_message, decoys, inputs, pseudo_blinding_factors, pseudo_amount_commits, i = 0]() mutable {
         const auto clsag = generate_clsag_signature
           (
            full_message
            , decoys[i]
            , inputs[i].input_spend_sk
            , inputs[i].input_blinding_factor
            , pseudo_blinding_factors[i]
            , pseudo_amount_commits[i]
            , inputs[i].index_in_decoys
            );
         i++;
         return toUnsafeCLSAG(clsag);
       }
       );

    rctData rctData = preRctSig;
    rctData.p.CLSAGs = clsags;

    return {rctData, output_blinding_factors};
  }

}
