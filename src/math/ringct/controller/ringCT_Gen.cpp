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

#include "ringCT_Gen.hpp"

#include "clsagGen.hpp"
#include "bulletproofs_gen.hpp"

#include "tools/epee/include/logging.hpp"

#include "math/ringct/functional/curveConstants.hpp"
#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/pseudo_functional/bulletproofs.hpp"
#include "math/ringct/pseudo_functional/ringCT.hpp"

#include "math/crypto/controller/keyGen.hpp"

#include "config/cryptonote.hpp"


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

namespace rct {

  std::tuple<rct_scalar, Bulletproof> generate_range_proof
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
         return
           {
             x.amount
             , rct::get_blinding_factor_from_hashed_shared_secret(x.ecdh_shared_secret_hashed_by_index)
           };
       }
       );

    const Bulletproof proof = bulletproof_MAKE(xs);

    LOG_ERROR_AND_THROW_UNLESS
      (
       proof.commits.size() == outputs.size()
       , "V does not have the expected size"
       );

    const rct_scalar output_blinding_factors_sum =
      std::transform_reduce
      (
       xs.begin()
       , xs.end()
       , s_zero
       , std::plus()
       , [](const auto& x) { return x.second; }
       );

    return {output_blinding_factors_sum, proof};
  }

  std::vector<std::pair<rct_scalar, rct_point>>
  generate_matching_input_commits(const rct_scalar match, const std::span<const amount_t> xs) {
    if (xs.empty()) return {};

    rct_scalarV bs;
    std::generate_n
      (
       std::back_inserter(bs)
       , xs.size() - 1
       , crypto::randomScalar
       );

    const rct_scalar last = match -
      std::reduce
      (
       bs.begin()
       , bs.end()
       , s_zero
       );

    bs.push_back(last);


    std::vector<std::pair<rct_scalar, rct_point>> r;
    std::transform
      (
       bs.begin()
       , bs.end()
       , xs.begin()
       , std::back_inserter(r)
       , [](const auto& b, const auto& x) -> std::pair<rct_scalar, rct_point> {
         return {b, commit(x, b)};
       }
       );

    return r;
  }

  rctData generate_ringct
  (
   const crypto::hash message
   , const std::vector<rctInputData> inputs
   , const std::vector<rctOutputData> outputs
   , const amount_t fee
   )
  {
    LOG_ERROR_AND_THROW_UNLESS(inputs.size() > 0, "Empty inamounts");

    for (size_t n = 0; n < inputs.size(); ++n) {
      LOG_ERROR_AND_THROW_UNLESS
        (
         inputs[n].index_in_decoys < inputs[n].decoys.size()
         , "Bad index into decoys"
         );
    }


    // 1. basic

    const auto [output_blinding_factors_sum, proof] = generate_range_proof(outputs);

    std::vector<output_commit> output_commits;
    std::transform
      (
       proof.commits.begin()
       , proof.commits.end()
       , std::back_inserter(output_commits)
       , [](const auto& x) -> output_commit {
         return {x};
       }
       );

    output_public_dataM decoys;
    std::transform
      (
       inputs.begin()
       , inputs.end()
       , std::back_inserter(decoys)
       , [](const auto x) -> output_public_dataV { return x.decoys; }
       );

    std::vector<ecdh_encrypted_data_t> ecdh;
    std::transform
      (
       outputs.begin(),
       outputs.end(),
       std::back_inserter(ecdh),
       [](const auto& x) -> ecdh_encrypted_data_t {
         return {
           encode_amount_by_hashed_ecdh_shared_secret(x.amount, x.ecdh_shared_secret_hashed_by_index)
         };
       }
       );

    const rctDataBasic rct_data_basic =
      { RCTTypeCLSAG
        , message
        , decoys
        , ecdh
        , output_commits
        , fee
      };


    // 2. prunable

    std::vector<amount_t> input_amounts;
    std::transform
      (
       inputs.begin()
       , inputs.end()
       , std::back_inserter(input_amounts)
       , [](const auto& x) { return x.amount; }
       );

    const std::vector<std::pair<rct_scalar, rct_point>> pseudo_inputs =
      generate_matching_input_commits(output_blinding_factors_sum, input_amounts);


    rct_pointV pseudo_input_commits;
    std::transform
      (
       pseudo_inputs.begin()
       , pseudo_inputs.end()
       , std::back_inserter(pseudo_input_commits)
       , [](const auto x) { return x.second; }
       );

    const auto unsafe_proof = toUnsafeBulletproof(proof);
    const rctDataPrunable dummy_rct_data_prunable_for_clsag_message_hash =
      {
        { unsafe_proof }
        , {}
        , pseudo_input_commits
      };

    const rctData dummy_rct_data_for_clsag_message_hash =
      {
        rct_data_basic
        , dummy_rct_data_prunable_for_clsag_message_hash
      };

    const auto maybeMessage = get_ring_signature_message(dummy_rct_data_for_clsag_message_hash);
    LOG_ERROR_AND_THROW_UNLESS(maybeMessage, "failed to generate rct message");

    const crypto::hash full_message = *maybeMessage;
    std::vector<clsag_unsafe> clsags;
    std::transform
      (
       inputs.begin()
       , inputs.end()
       , pseudo_inputs.begin()
       , std::back_inserter(clsags)
       , [ full_message ] (const auto& i, const auto& p) {
         const auto clsag = generate_clsag_signature
           (
            full_message
            , i.signer_sk
            , i.signer_blinding_factor
            , i.index_in_decoys
            , p.first
            , p.second
            , i.decoys
            );
         return toUnsafeCLSAG(clsag);
       }
       );

    return rctData {
      rct_data_basic
      , {
        { unsafe_proof }
        , clsags
        , pseudo_input_commits
      }
    };
  }

}
