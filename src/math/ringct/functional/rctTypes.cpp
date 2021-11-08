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

#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/int-util.h"

#include "config/cryptonote.hpp"

#include <cstring>

using namespace std;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

namespace rct {

    //Various Conversions

    rct_point rct_point::operator+(const rct_point& y) const
    {
      return p2rct_p(ec_point::operator+(y));
    }

    rct_point rct_point::operator-(const rct_point& y) const
    {
      return p2rct_p(ec_point::operator-(y));
    }

    rct_point rct_point::operator^(const rct_scalar& y) const
    {
      return p2rct_p(ec_point::operator^(y));
    }

    bool rct_point::operator<(const rct_point& y) const
    {
      return std::strncmp((const char*)data.data(), (const char*)y.data.data(), data.size()) < 0;
    }

    std::optional<rct_point> maybeSafeRctPoint(const crypto::ec_point_unsafe x) noexcept {
      const auto p = crypto::maybeSafePoint(x);

      if (p) {
        return p2rct_p(*p);
      } else {
        return {};
      }
    };


    rct_scalar rct_scalar::operator+(const rct_scalar& y) const
    {
      return s2s(ec_scalar::operator+(y));
    }

    rct_scalar rct_scalar::operator-(const rct_scalar& y) const
    {
      return s2s(ec_scalar::operator-(y));
    }

    rct_scalar rct_scalar::operator*(const rct_scalar& y) const
    {
      return s2s(ec_scalar::operator*(y));
    }

    rct_scalar int_to_scalar(const amount_t in) {
      return s2s(crypto::int_to_scalar(in));
    }

    amount_t scalar_to_int(const rct_scalar & in) {
      return crypto::scalar_to_int(in);
    }

    size_t n_bulletproof_amounts(const Bulletproof &proof)
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

    size_t n_bulletproof_amounts(const std::vector<Bulletproof> &proofs)
    {
        size_t n = 0;
        for (const Bulletproof &proof: proofs)
        {
            size_t n2 = n_bulletproof_amounts(proof);
            LOG_ERROR_AND_RETURN_UNLESS(n2 < std::numeric_limits<uint32_t>::max() - n, 0, "Invalid number of bulletproofs");
            if (n2 == 0)
                return 0;
            n += n2;
        }
        return n;
    }

    size_t n_bulletproof_max_amounts(const Bulletproof &proof)
    {
        LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() >= 6, 0, "Invalid bulletproof L size");
        LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() == proof.R.size(), 0, "Mismatched bulletproof L/R size");
        static const size_t extra_bits = 4;
        static_assert((1 << extra_bits) == constant::BULLETPROOF_MAX_OUTPUTS, "log2(constant::BULLETPROOF_MAX_OUTPUTS) is out of date");
        LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() <= 6 + extra_bits, 0, "Invalid bulletproof L size");
        return 1 << (proof.L.size() - 6);
    }

    size_t n_bulletproof_max_amounts(const std::vector<Bulletproof> &proofs)
    {
        size_t n = 0;
        for (const Bulletproof &proof: proofs)
        {
            size_t n2 = n_bulletproof_max_amounts(proof);
            LOG_ERROR_AND_RETURN_UNLESS(n2 < std::numeric_limits<uint32_t>::max() - n, 0, "Invalid number of bulletproofs");
            if (n2 == 0)
                return 0;
            n += n2;
        }
        return n;
    }

   std::optional<Bulletproof_safe> maybeSafeBulletproof(const Bulletproof proof) {
      const auto maybe_proof_A = maybeSafeRctPoint(proof.A);
      LOG_ERROR_AND_RETURN_UNLESS(maybe_proof_A, {}, "Bad proof.A");
      const rct::rct_point proof_A = *maybe_proof_A;

      const auto maybe_proof_S = maybeSafeRctPoint(proof.S);
      LOG_ERROR_AND_RETURN_UNLESS(maybe_proof_S, {}, "Bad proof.S");
      const rct::rct_point proof_S = *maybe_proof_S;

      const auto maybe_proof_T1 = maybeSafeRctPoint(proof.T1);
      LOG_ERROR_AND_RETURN_UNLESS(maybe_proof_T1, {}, "Bad proof.T1");
      const rct::rct_point proof_T1 = *maybe_proof_T1;

      const auto maybe_proof_T2 = maybeSafeRctPoint(proof.T2);
      LOG_ERROR_AND_RETURN_UNLESS(maybe_proof_T2, {}, "Bad proof.T2");
      const rct::rct_point proof_T2 = *maybe_proof_T2;

      std::vector<rct::rct_point> proof_V;
      for (const auto& x: proof.V) {
        const auto y = maybeSafeRctPoint(x);
        LOG_ERROR_AND_RETURN_UNLESS(y, {}, "Bad proof.V");
        proof_V.push_back(*y);
      }

      std::vector<rct::rct_point> proof_L;
      for (const auto& x: proof.L) {
        const auto y = maybeSafeRctPoint(x);
        LOG_ERROR_AND_RETURN_UNLESS(y, {}, "Bad proof.L");
        proof_L.push_back(*y);
      }

      std::vector<rct::rct_point> proof_R;
      for (const auto& x: proof.R) {
        const auto y = maybeSafeRctPoint(x);
        LOG_ERROR_AND_RETURN_UNLESS(y, {}, "Bad proof.R");
        proof_R.push_back(*y);
      }

      return Bulletproof_safe {
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
        , proof.taux
        , proof.mu
        , proof_L
        , proof_R
        , proof.a
        , proof.b
        , proof.t
      };
   }

  Bulletproof toBulletproof(const Bulletproof_safe proof) {
    return Bulletproof {
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

}
