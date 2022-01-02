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

#include "math/consensus/consensus.hpp"

#include <cstring>




namespace rct {

  size_t n_bulletproof_max_commit_size(const Bulletproof_unsafe &proof)
  {
    return 1 << (proof.L.size() - 6);
  }

  std::optional<Bulletproof> maybeSafeBulletproof(const Bulletproof_unsafe proof) {
    const auto maybe_proof_A = maybe_from_inv8(proof.A);
    LOG_ERROR_AND_RETURN_UNLESS(maybe_proof_A, {}, "Bad proof.A");
    const crypto::ec_point proof_A = *maybe_proof_A;

    const auto maybe_proof_S = maybe_from_inv8(proof.S);
    LOG_ERROR_AND_RETURN_UNLESS(maybe_proof_S, {}, "Bad proof.S");
    const crypto::ec_point proof_S = *maybe_proof_S;

    const auto maybe_proof_T1 = maybe_from_inv8(proof.T1);
    LOG_ERROR_AND_RETURN_UNLESS(maybe_proof_T1, {}, "Bad proof.T1");
    const crypto::ec_point proof_T1 = *maybe_proof_T1;

    const auto maybe_proof_T2 = maybe_from_inv8(proof.T2);
    LOG_ERROR_AND_RETURN_UNLESS(maybe_proof_T2, {}, "Bad proof.T2");
    const crypto::ec_point proof_T2 = *maybe_proof_T2;

    std::vector<crypto::ec_point> proof_L;
    for (const auto& x: proof.L) {
      const auto y = maybe_from_inv8(x);
      LOG_ERROR_AND_RETURN_UNLESS(y, {}, "Bad proof.L");
      proof_L.push_back(*y);
    }

    std::vector<crypto::ec_point> proof_R;
    for (const auto& x: proof.R) {
      const auto y = maybe_from_inv8(x);
      LOG_ERROR_AND_RETURN_UNLESS(y, {}, "Bad proof.R");
      proof_R.push_back(*y);
    }

    // check crypto::ec_scalar range
    LOG_ERROR_AND_RETURN_UNLESS(is_reduced(proof.taux), {}, "Input crypto::ec_scalar not in range");
    LOG_ERROR_AND_RETURN_UNLESS(is_reduced(proof.mu), {}, "Input crypto::ec_scalar not in range");

    LOG_ERROR_AND_RETURN_UNLESS(is_reduced(proof.a), {}, "Input crypto::ec_scalar not in range");
    LOG_ERROR_AND_RETURN_UNLESS(is_reduced(proof.b), {}, "Input crypto::ec_scalar not in range");
    LOG_ERROR_AND_RETURN_UNLESS(is_reduced(proof.t), {}, "Input crypto::ec_scalar not in range");

    const auto maybeLR = zipLR(proof_L, proof_R);
    LOG_ERROR_AND_RETURN_UNLESS(maybeLR, {}, "failed to construct LR from L and R");

    return Bulletproof {
      // rct::inv8V V;
      // rct::inv8 A, S;
      // rct::inv8 T1, T2;
      // crypto::ec_scalar taux;
      // crypto::ec_scalar mu;
      // rct::inv8V L, R;
      // crypto::ec_scalar a, b, t;
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
      // crypto::ec_scalar taux;
      // crypto::ec_scalar mu;
      // rct::inv8V L, R;
      // crypto::ec_scalar a, b, t;
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

    // scalarV s; // scalars
    // crypto::ec_scalar c1;

    // crypto::ec_point I; // signing key image
    // crypto::ec_point D; // commitment key image

    scalarV clsag_s;
    for (const auto& x: clsag.s) {
      LOG_ERROR_AND_RETURN_UNLESS(crypto::is_reduced(x), {}, "Bad clsag.s");
      clsag_s.push_back(crypto::reduce(x));
    }

    LOG_ERROR_AND_RETURN_UNLESS(crypto::is_reduced(clsag.c1), {}, "Bad clsag.c1");

    const auto maybe_clsag_blinding_factor_surplus_key_image =
      maybe_from_inv8(clsag.blinding_factor_surplus_key_image);

    LOG_ERROR_AND_RETURN_UNLESS
      (
       maybe_clsag_blinding_factor_surplus_key_image
       , {}
       , "Bad clsag.blinding_factor_surplus_key_image"
       );

    const crypto::ec_point clsag_blinding_factor_surplus_key_image =
      *maybe_clsag_blinding_factor_surplus_key_image;

    return {{
      clsag_s
      , crypto::reduce(clsag.c1)
      , clsag.signer_key_image
      , clsag_blinding_factor_surplus_key_image
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
      , to_inv8(clsag.blinding_factor_surplus_key_image)
    };
  }

  const rct::inv8V to_inv8V(const pointS xs) {
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


  std::optional<LR_V> zipLR(const pointV L, const pointV R) {
    if (L.size() != R.size()) {
      return {};
    }

    std::vector<std::pair<crypto::ec_point, crypto::ec_point>> LR;

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

  std::pair<pointV, pointV>
  splitLR(const std::span<const std::pair<crypto::ec_point, crypto::ec_point>> LR) {
    pointV L;
    pointV R;

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
