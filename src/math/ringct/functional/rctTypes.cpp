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

using namespace std;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

namespace rct {

    size_t n_bulletproof_amounts(const Bulletproof_unsafe &proof)
    {
        LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() >= 6, 0, "Invalid bulletproof L size");
        LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() == proof.R.size(), 0, "Mismatched bulletproof L/R size");
        static const size_t extra_bits = 4;
        static_assert((1 << extra_bits) == constant::BULLETPROOF_MAX_OUTPUTS, "log2(constant::BULLETPROOF_MAX_OUTPUTS) is out of date");
        LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() <= 6 + extra_bits, 0, "Invalid bulletproof L size");
        LOG_ERROR_AND_RETURN_UNLESS(proof.V.size() <= (1u<<(proof.L.size()-6)), 0, "Invalid bulletproof V/L");
        LOG_ERROR_AND_RETURN_UNLESS(proof.V.size() * 2 > (1u<<(proof.L.size()-6)), 0, "Invalid bulletproof V/L");
        LOG_ERROR_AND_RETURN_UNLESS(proof.V.size() > 0, 0, "Empty bulletproof");
        return proof.V.size();
    }

    size_t n_bulletproof_amounts(const std::vector<Bulletproof_unsafe> &proofs)
    {
        size_t n = 0;
        for (const Bulletproof_unsafe &proof: proofs)
        {
            size_t n2 = n_bulletproof_amounts(proof);
            LOG_ERROR_AND_RETURN_UNLESS(n2 < std::numeric_limits<uint32_t>::max() - n, 0, "Invalid number of bulletproofs");
            if (n2 == 0)
                return 0;
            n += n2;
        }
        return n;
    }

    size_t n_bulletproof_max_amounts(const Bulletproof_unsafe &proof)
    {
        LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() >= 6, 0, "Invalid bulletproof L size");
        LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() == proof.R.size(), 0, "Mismatched bulletproof L/R size");
        static const size_t extra_bits = 4;
        static_assert((1 << extra_bits) == constant::BULLETPROOF_MAX_OUTPUTS, "log2(constant::BULLETPROOF_MAX_OUTPUTS) is out of date");
        LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() <= 6 + extra_bits, 0, "Invalid bulletproof L size");
        return 1 << (proof.L.size() - 6);
    }

    size_t n_bulletproof_max_amounts(const std::vector<Bulletproof_unsafe> &proofs)
    {
        size_t n = 0;
        for (const Bulletproof_unsafe &proof: proofs)
        {
            size_t n2 = n_bulletproof_max_amounts(proof);
            LOG_ERROR_AND_RETURN_UNLESS(n2 < std::numeric_limits<uint32_t>::max() - n, 0, "Invalid number of bulletproofs");
            if (n2 == 0)
                return 0;
            n += n2;
        }
        return n;
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

      std::vector<rct::rct_point> proof_V;
      for (const auto& x: proof.V) {
        const auto y = crypto::maybeSafePoint(x);
        LOG_ERROR_AND_RETURN_UNLESS(y, {}, "Bad proof.V");
        proof_V.push_back(*y);
      }

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


      return Bulletproof {
        // rct::inv8V V;
        // rct::inv8 A, S;
        // rct::inv8 T1, T2;
        // rct::rct_scalar taux;
        // rct::rct_scalar mu;
        // rct::inv8V L, R;
        // rct::rct_scalar a, b, t;
        proof_V
        , proof_A
        , proof_S
        , proof_T1
        , proof_T2
        , crypto::reduce(proof.taux)
        , crypto::reduce(proof.mu)
        , proof_L
        , proof_R
        , crypto::reduce(proof.a)
        , crypto::reduce(proof.b)
        , crypto::reduce(proof.t)
      };
   }

  Bulletproof_unsafe toUnsafeBulletproof(const Bulletproof proof) {
    return Bulletproof_unsafe {
      // rct::inv8V V;
      // rct::inv8 A, S;
      // rct::inv8 T1, T2;
      // rct::rct_scalar taux;
      // rct::rct_scalar mu;
      // rct::inv8V L, R;
      // rct::rct_scalar a, b, t;
      to_inv8V(proof.V)
      , proof.A
      , proof.S
      , proof.T1
      , proof.T2
      , proof.taux
      , proof.mu
      , to_inv8V(proof.L)
      , to_inv8V(proof.R)
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
      clsag_s.push_back(rct_reduce(x));
    }

    LOG_ERROR_AND_RETURN_UNLESS(crypto::is_reduced(clsag.c1), {}, "Bad clsag.c1");

    const auto maybe_clsag_D = crypto::maybeSafePoint(clsag.D);
    LOG_ERROR_AND_RETURN_UNLESS(maybe_clsag_D, {}, "Bad clsag.D");
    const rct::rct_point clsag_D = *maybe_clsag_D;

    const auto maybe_clsag_I = crypto::maybeSafePoint(clsag.I);
    LOG_ERROR_AND_RETURN_UNLESS(maybe_clsag_I, {}, "Bad clsag.I");
    const rct::rct_point clsag_I = *maybe_clsag_I;

    return {{
      clsag_s
      , rct_reduce(clsag.c1)
      , clsag_I
      , clsag_D
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
      , clsag.I
      , clsag.D
    };
  }

}
