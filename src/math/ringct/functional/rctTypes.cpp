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

#include "rctTypes.hpp"
#include "rctOps.hpp"

#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/int-util.h"

#include "config/cryptonote.hpp"

#include "consensus/consensus.hpp"

#include <cstring>




namespace rct {

  size_t n_bulletproof_max_commit_size(const Bulletproof_unsafe &proof)
  {
    return 1 << (proof.L.size() - 6);
  }

  std::optional<Bulletproof> maybeSafeBulletproof(const Bulletproof_unsafe proof) {
    const auto maybe_proof_A = maybe_from_inv8(proof.A);
    LOG_ERROR_AND_RETURN_UNLESS(maybe_proof_A, {}, "Bad proof.A");
    const rct::rct_point proof_A = *maybe_proof_A;

    const auto maybe_proof_S = maybe_from_inv8(proof.S);
    LOG_ERROR_AND_RETURN_UNLESS(maybe_proof_S, {}, "Bad proof.S");
    const rct::rct_point proof_S = *maybe_proof_S;

    const auto maybe_proof_T1 = maybe_from_inv8(proof.T1);
    LOG_ERROR_AND_RETURN_UNLESS(maybe_proof_T1, {}, "Bad proof.T1");
    const rct::rct_point proof_T1 = *maybe_proof_T1;

    const auto maybe_proof_T2 = maybe_from_inv8(proof.T2);
    LOG_ERROR_AND_RETURN_UNLESS(maybe_proof_T2, {}, "Bad proof.T2");
    const rct::rct_point proof_T2 = *maybe_proof_T2;

    std::vector<rct::rct_point> proof_L;
    for (const auto& x: proof.L) {
      const auto y = maybe_from_inv8(x);
      LOG_ERROR_AND_RETURN_UNLESS(y, {}, "Bad proof.L");
      proof_L.push_back(*y);
    }

    std::vector<rct::rct_point> proof_R;
    for (const auto& x: proof.R) {
      const auto y = maybe_from_inv8(x);
      LOG_ERROR_AND_RETURN_UNLESS(y, {}, "Bad proof.R");
      proof_R.push_back(*y);
    }

    // check rct_scalar range
    LOG_ERROR_AND_RETURN_UNLESS(is_reduced(proof.taux), {}, "Input rct_scalar not in range");
    LOG_ERROR_AND_RETURN_UNLESS(is_reduced(proof.mu), {}, "Input rct_scalar not in range");

    LOG_ERROR_AND_RETURN_UNLESS(is_reduced(proof.a), {}, "Input rct_scalar not in range");
    LOG_ERROR_AND_RETURN_UNLESS(is_reduced(proof.b), {}, "Input rct_scalar not in range");
    LOG_ERROR_AND_RETURN_UNLESS(is_reduced(proof.t), {}, "Input rct_scalar not in range");

    const auto maybeLR = zipLR(proof_L, proof_R);
    LOG_ERROR_AND_RETURN_UNLESS(maybeLR, {}, "failed to construct LR from L and R");

    return Bulletproof {
      // rct::inv8V V;
      // rct::inv8 A, S;
      // rct::inv8 T1, T2;
      // rct::rct_scalar taux;
      // rct::rct_scalar mu;
      // rct::inv8V L, R;
      // rct::rct_scalar a, b, t;
      proof_A
      , proof_S
      , proof_T1
      , proof_T2
      , crypto::reduce(proof.taux)
      , crypto::reduce(proof.mu)
      , *maybeLR
      , crypto::reduce(proof.a)
      , crypto::reduce(proof.b)
      , crypto::reduce(proof.t)
    };
  }

  Bulletproof_unsafe toUnsafeBulletproof(const Bulletproof proof) {
    const auto& [L, R] = splitLR(proof.LR);
    return Bulletproof_unsafe {
      // rct::inv8V V;
      // rct::inv8 A, S;
      // rct::inv8 T1, T2;
      // rct::rct_scalar taux;
      // rct::rct_scalar mu;
      // rct::inv8V L, R;
      // rct::rct_scalar a, b, t;
      to_inv8(proof.A)
      , to_inv8(proof.S)
      , to_inv8(proof.T1)
      , to_inv8(proof.T2)
      , proof.taux
      , proof.mu
      , to_inv8V(L)
      , to_inv8V(R)
      , proof.a
      , proof.b
      , proof.t
    };
  }

  std::optional<clsag> maybeSafeCLSAG(const clsag_unsafe clsag) {

    // rct_scalarV s; // scalars
    // rct_scalar c1;

    // rct_point I; // signing key image
    // rct_point D; // commitment key image

    rct_scalarV clsag_s;
    for (const auto& x: clsag.s) {
      LOG_ERROR_AND_RETURN_UNLESS(crypto::is_reduced(x), {}, "Bad clsag.s");
      clsag_s.push_back(crypto::reduce(x));
    }

    LOG_ERROR_AND_RETURN_UNLESS(crypto::is_reduced(clsag.c1), {}, "Bad clsag.c1");

    const auto maybe_clsag_blinding_factor_surplus_pk_base_hashed_signer_pk =
      maybe_from_inv8(clsag.blinding_factor_surplus_pk_base_hashed_signer_pk);

    LOG_ERROR_AND_RETURN_UNLESS
      (
       maybe_clsag_blinding_factor_surplus_pk_base_hashed_signer_pk
       , {}
       , "Bad clsag.blinding_factor_surplus_pk_base_hashed_signer_pk"
       );

    const rct::rct_point clsag_blinding_factor_surplus_pk_base_hashed_signer_pk =
      *maybe_clsag_blinding_factor_surplus_pk_base_hashed_signer_pk;

    return {{
      clsag_s
      , crypto::reduce(clsag.c1)
      , clsag.signer_key_image
      , clsag_blinding_factor_surplus_pk_base_hashed_signer_pk
    }};
  }

  clsag_unsafe toUnsafeCLSAG(const clsag clsag) {
    std::vector<crypto::ec_scalar_unnormalized> s; // scalars
    for (const auto& x: clsag.s) {
      s.push_back(x);
    }

    return {
      s
      , clsag.c1
      , clsag.signer_key_image
      , to_inv8(clsag.blinding_factor_surplus_pk_base_hashed_signer_pk)
    };
  }

  const rct::inv8V to_inv8V(const rct_pointS xs) {
    inv8V ys;
    std::transform
      (
       xs.begin()
       , xs.end()
       , std::back_inserter(ys)
       , [](const auto& x) { return to_inv8(x); }
       );

    return ys;
  }


  std::optional<LR_V> zipLR(const rct_pointV L, const rct_pointV R) {
    if (L.size() != R.size()) {
      return {};
    }

    std::vector<std::pair<rct_point, rct_point>> LR;

    std::transform
      (
       L.begin()
       , L.end()
       , R.begin()
       , std::back_inserter(LR)
       , [](const auto& x, const auto& y) { return std::make_pair(x, y); }
       );

    return LR;
  }

  std::pair<rct_pointV, rct_pointV>
  splitLR(const std::span<const std::pair<rct_point, rct_point>> LR) {
    rct_pointV L;
    rct_pointV R;

    std::transform
      (
       LR.begin()
       , LR.end()
       , std::back_inserter(L)
       , [](const auto& x) { return x.first; }
       );

    std::transform
      (
       LR.begin()
       , LR.end()
       , std::back_inserter(R)
       , [](const auto& x) { return x.second; }
       );

    return {L, R};
  }

  std::optional<rctDataSizeChecked> maybeSizeCheckedRctData(const rctData& x) {

    LOG_ERROR_AND_RETURN_UNLESS
      (
       x.type == RCTTypeCLSAG
       , {}
       , "Checking rct data on non ringct"
       );

    const std::optional<Bulletproof_unsafe> maybe_proof =
      consensus::rule_17_ringct_should_contain_only_one_range_proof(x.p.bulletproofs);

    LOG_ERROR_AND_RETURN_UNLESS
      (
       maybe_proof
       , {}
       , "More than one proofs"
       );

    const auto proof = *maybe_proof;

    LOG_ERROR_AND_RETURN_UNLESS
      (
       x.p.pseudo_input_commits.size() == x.p.CLSAGs.size()
       , {}
       , "Mismatched sizes of rv.p.pseudo_input_commits and rv.p.CLSAGs"
       );

    LOG_ERROR_AND_RETURN_UNLESS
      (
       x.output_commits.size() == x.ecdh_encrypted_data.size()
       , {}
       , "Mismatched sizes of output_commits and rv.ecdh_encrypted_data"
       );

    const rctDataSizeChecked r = {
      x
      , proof
      , x.p.CLSAGs
      , x.p.pseudo_input_commits
    };

    return r;
  }

  rctData toRctData(const rctDataSizeChecked& x) {
    return {
      x
      , {
        { x.bulletproof }
        , x.CLSAGs
        , x.pseudo_input_commits
      }
    };
  }

}
