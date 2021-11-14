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

#include <cstring>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

namespace rct {

  bool is_bulletproof_structure_valid(const Bulletproof_unsafe &proof) {
    LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() >= 6, false, "Invalid bulletproof L size");
    LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() == proof.R.size(), false, "Mismatched bulletproof L/R size");

    constexpr size_t extra_bits = 4;
    static_assert
      (
       (1 << extra_bits) == constant::BULLETPROOF_MAX_OUTPUTS
       , "log2(constant::BULLETPROOF_MAX_OUTPUTS) is out of date"
       );

    LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() <= 6 + extra_bits, false, "Invalid bulletproof L size");

    return true;
  }

  bool is_bulletproof_structure_valid_extended(const Bulletproof_unsafe &proof) {
    LOG_ERROR_AND_RETURN_UNLESS
      (
       proof.commits.size() <= (1u<<(proof.L.size()-6))
       , false
       , "Invalid bulletproof V/L"
       );

    LOG_ERROR_AND_RETURN_UNLESS
      (
       proof.commits.size() * 2 > (1u<<(proof.L.size()-6))
       , false
       , "Invalid bulletproof V/L"
       );

    LOG_ERROR_AND_RETURN_UNLESS(proof.commits.size() > 0, false, "Empty bulletproof");

    return true;
  }

  size_t n_bulletproof_amounts(const Bulletproof_unsafe &proof)
  {
    LOG_ERROR_AND_RETURN_UNLESS(is_bulletproof_structure_valid_extended(proof), 0, "Invalid proof structure");
    return proof.commits.size();
  }

  size_t n_bulletproof_max_amounts(const Bulletproof_unsafe &proof)
  {
    return 1 << (proof.L.size() - 6);
  }

  std::optional<Bulletproof> maybeSafeBulletproof(const Bulletproof_unsafe proof) {
    const auto maybe_proof_A = crypto::maybeSafePoint(proof.A);
    LOG_ERROR_AND_RETURN_UNLESS(maybe_proof_A, {}, "Bad proof.A");
    const rct::rct_point proof_A = *maybe_proof_A;

    const auto maybe_proof_S = crypto::maybeSafePoint(proof.S);
    LOG_ERROR_AND_RETURN_UNLESS(maybe_proof_S, {}, "Bad proof.S");
    const rct::rct_point proof_S = *maybe_proof_S;

    const auto maybe_proof_T1 = crypto::maybeSafePoint(proof.T1);
    LOG_ERROR_AND_RETURN_UNLESS(maybe_proof_T1, {}, "Bad proof.T1");
    const rct::rct_point proof_T1 = *maybe_proof_T1;

    const auto maybe_proof_T2 = crypto::maybeSafePoint(proof.T2);
    LOG_ERROR_AND_RETURN_UNLESS(maybe_proof_T2, {}, "Bad proof.T2");
    const rct::rct_point proof_T2 = *maybe_proof_T2;

    std::vector<rct::rct_point> proof_L;
    for (const auto& x: proof.L) {
      const auto y = crypto::maybeSafePoint(x);
      LOG_ERROR_AND_RETURN_UNLESS(y, {}, "Bad proof.L");
      proof_L.push_back(*y);
    }

    std::vector<rct::rct_point> proof_R;
    for (const auto& x: proof.R) {
      const auto y = crypto::maybeSafePoint(x);
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
      proof.commits
      , proof_A
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
      proof.commits
      , proof.A
      , proof.S
      , proof.T1
      , proof.T2
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

    const auto maybe_clsag_signer_pk_image_from_blinding_surplus =
      crypto::maybeSafePoint(clsag.signer_pk_image_from_blinding_surplus);

    LOG_ERROR_AND_RETURN_UNLESS
      (
       maybe_clsag_signer_pk_image_from_blinding_surplus
       , {}
       , "Bad clsag.signer_pk_image_from_blinding_surplus"
       );

    const rct::rct_point clsag_signer_pk_image_from_blinding_surplus =
      *maybe_clsag_signer_pk_image_from_blinding_surplus;

    return {{
      clsag_s
      , crypto::reduce(clsag.c1)
      , clsag.signer_pk_image
      , clsag_signer_pk_image_from_blinding_surplus
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
      , clsag.signer_pk_image
      , clsag.signer_pk_image_from_blinding_surplus
    };
  }

  const rct::inv8V to_inv8V(const rct_pointS xs) {
    inv8V ys;
    std::transform
      (
       xs.begin()
       , xs.end()
       , std::back_inserter(ys)
       , [](const auto& x) { return x; }
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

}
