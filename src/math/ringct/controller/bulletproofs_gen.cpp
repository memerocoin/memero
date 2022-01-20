/*

  Copyright 2021 fuwa

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/


// Copyright (c) 2021, The Lolnero Project
// Copyright (c) 2017-2020, The Monero Project
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
// Adapted from Java code by Sarang Noether
// Paper references are to https://eprint.iacr.org/2017/1066 (revision 1 July 2018)

#include "bulletproofs_gen.hpp"

#include "math/ringct/functional/vectorOps.hpp"
#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/functional/curveConstants.hpp"
#include "math/ringct/functional/bulletproofs.hpp"
#include "math/ringct/functional/accumHash.hpp"

#include "math/crypto/controller/keyGen.hpp"

#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/string_tools.h"
#include "tools/common/varint.h"

#include <atomic>
#include <numeric>


namespace rct
{

  const scalarV twoN = vector_exponents(rct::s_two, bit_width);

  std::array<crypto::ec_point, bit_width * max_outputs> H_V;
  std::array<crypto::ec_point, bit_width * max_outputs> G_V;

  crypto::ec_point get_bp_generator(const crypto::ec_point base, size_t idx)
  {
    constexpr std::string_view domain_separator =
      config::HASH_KEY_BULLETPROOF_EXPONENT;

    const std::string hashed =
      epee::string_tools::blob_to_string(base.data)
      + std::string(domain_separator)
      + tools::get_varint_data(idx);

    crypto::ec_point e = crypto::hash_to_point_via_field
      ( crypto::h2d(crypto::sha3(epee::string_tools::string_to_blob(hashed))) );

    LOG_ERROR_AND_THROW_IF((e == crypto::identity), "Invalid exponent");
    return e;
  }

  crypto::ec_point get_bp_generator_G(const size_t idx) {
    return get_bp_generator(H, idx * 2);
  }

  crypto::ec_point get_bp_generator_H(const size_t idx) {
    return get_bp_generator(H, idx * 2 + 1);
  }

  std::atomic<bool> init_done(false);
  std::mutex init_mutex;

  void init_generators()
  {
    if (!init_done) {
      std::lock_guard<std::mutex> lock(init_mutex);
      std::generate
        (
         H_V.begin()
         , H_V.end()
         , [i = 0] () mutable {
           const auto r = get_bp_generator_G(i);
           i++;
           return r;
         }
         );

      std::generate
        (
         G_V.begin()
         , G_V.end()
         , [i = 0] () mutable {
           const auto r = get_bp_generator_H(i);
           i++;
           return r;
         }
         );

      init_done = true;
    }
  }


  crypto::ec_point commit_vectors_with_bp_generators_G_H
  (
   const scalarS a
   , const scalarS b
   )
  {
    LOG_ERROR_AND_THROW_UNLESS
      (a.size() == b.size(), "Incompatible sizes of a and b");

    LOG_ERROR_AND_THROW_UNLESS
      (a.size() <= max_vector_length, "vector size too big");

    return vector_commit(a, G_V) + vector_commit(b, H_V);
  }

  pointV vector_mult_both
  (
   const pointS vl
   , const pointS vr
   , const scalarS a
   , const scalarS b
   )
  {
    LOG_ERROR_AND_THROW_UNLESS(vl.size() == vr.size(), "Vector size should be even");

    const pointV l = vector_multV(a, vl);
    const pointV r = vector_multV(b, vr);

    return vector_addV(l, r);
  }

  crypto::ec_point vector_commit_both
  (
   const pointS vl
   , const pointS vr
   , const scalarS a
   , const scalarS b
   ) {
    const auto xs = vector_mult_both(vl, vr, a, b);
    return std::reduce(xs.begin(), xs.end(), crypto::identity);
  }

  Bulletproof bulletproof_MAKE(const std::span<const bp_input_t> xs)
  {
    LOG_ERROR_AND_THROW_UNLESS(!xs.empty(), "Nothing to proof");
    LOG_ERROR_AND_THROW_UNLESS(xs.size() <= max_outputs, "too many amounts to proof");

    for (const auto& [x,g]: xs) {
      LOG_ERROR_AND_THROW_UNLESS(is_reduced(g), "Invalid gamma input");
    }

    init_generators();

    const auto [N, logN] = log2bound(bit_width);
    const auto [M, logM] = log2bound(xs.size());

    const size_t MN = M * N;

    pointV V(xs.size());
    scalarV aL(MN), aR(MN);

    std::transform
      (
       xs.begin()
       , xs.end()
       , V.begin()
       , [](const auto& x) {
         return std::apply(commit, x);
       }
       );

    // PAPER LINES 41-42
    for (size_t j = 0; j < M; ++j)
      {
        for (size_t i = N; i-- > 0; )
          {
            const crypto::ec_scalar amount_scalar = crypto::int_to_scalar(xs[j].first);
            if (j < xs.size() && (amount_scalar.data[i/8] & (((uint64_t)1)<<(i%8))))
              {
                aL[j*N+i] = rct::s_one;
                aR[j*N+i] = rct::s_zero;
              }
            else
              {
                aL[j*N+i] = rct::s_zero;
                aR[j*N+i] = rct::s_minus_one;
              }
          }
      }

  try_again:
    // PAPER LINES 43-44
    const crypto::ec_scalar alpha = crypto::randomScalar();
    const crypto::ec_point A =
      commit_vectors_with_bp_generators_G_H(aL, aR) + G_(alpha);

    // PAPER LINES 45-47
    const scalarV sL = crypto::randomScalars(MN);
    const scalarV sR = crypto::randomScalars(MN);
    const crypto::ec_scalar rho = crypto::randomScalar();
    const crypto::ec_point S =
      commit_vectors_with_bp_generators_G_H(sL, sR) + G_(rho);

    crypto::dataV commit_data_V;
    std::transform
      (
       V.begin()
       , V.end()
       , std::back_inserter(commit_data_V)
       , to_inv8
       );

    const auto maybe_pd_y = accum_hash
      (
       {}
       , {
         commit_data_V
         , { to_inv8(A), to_inv8(S) }
       }
       );

    // PAPER LINES 48-50
    if (!maybe_pd_y)
      {
        LOG_INFO("y is 0, trying again");
        goto try_again;
      }

    const auto pd_y_array = *maybe_pd_y;
    const auto y = pd_y_array.back();

    const crypto::ec_scalar z = rct::hash_to_scalar(y);
    if (z == rct::s_zero)
      {
        LOG_INFO("z is 0, trying again");
        goto try_again;
      }

    // Polynomial construction by coefficients
    // PAPER LINES 70-71
    const scalarV l0 = vector_subtract(aL, z);
    const scalarS l1 = sL;

    scalarV zero_twos(MN);
    const scalarV zpow = vector_exponents(z, M+2);
    for (size_t j = 0; j < M; ++j)
      {
        for (size_t i = 0; i < N; ++i)
          {
            LOG_ERROR_AND_THROW_UNLESS(j+2 < zpow.size(), "invalid zpow index");
            LOG_ERROR_AND_THROW_UNLESS(i < twoN.size(), "invalid twoN index");
            zero_twos[j*N+i] = zpow[j+2] * twoN[i];
          }
      }

    const auto yMN = vector_exponents(y, MN);
    const scalarV r0 = vector_addV
      (
       hadamard_product(vector_add(aR, z), yMN)
       , zero_twos
       );

    const scalarV r1 = hadamard_product(yMN, sR);

    // Polynomial construction before PAPER LINE 51
    const crypto::ec_scalar t1_1 = inner_product(l0, r1);
    const crypto::ec_scalar t1_2 = inner_product(l1, r0);
    const crypto::ec_scalar t1 = t1_1 + t1_2;
    const crypto::ec_scalar t2 = inner_product(l1, r1);

    // PAPER LINES 52-53
    const crypto::ec_scalar tau1 = crypto::randomScalar();
    const crypto::ec_scalar tau2 = crypto::randomScalar();

    const crypto::ec_point T1 = G_(tau1) + H_(t1);
    const crypto::ec_point T2 = G_(tau2) + H_(t2);

    // PAPER LINES 54-56
    const crypto::ec_scalar x = hash_dataV_to_scalar
      (crypto::dataV{z, z, to_inv8(T1), to_inv8(T2)});
    if (x == rct::s_zero)
      {
        LOG_INFO("x is 0, trying again");
        goto try_again;
      }

    // PAPER LINES 61-63
    const crypto::ec_scalar xsq = x * x;

    LOG_ERROR_AND_THROW_UNLESS(xs.size()+1 < zpow.size(), "invalid zpow index");

    scalarV blinding_factors;
    std::transform
      (
       xs.begin()
       , xs.end()
       , std::back_inserter(blinding_factors)
       , [](const auto&x ) { return x.second; }
       );

    const crypto::ec_scalar taux1 =
      inner_product(blinding_factors, std::span(zpow).subspan(2));

    const crypto::ec_scalar taux = tau1 * x + tau2 * xsq + taux1;

    const crypto::ec_scalar mu = x * rho + alpha;

    // PAPER LINES 58-60
    const scalarV l = vector_addV(l0, vector_mult(l1, x));
    const scalarV r = vector_addV(r0, vector_mult(r1, x));

    const crypto::ec_scalar t = inner_product(l, r);

    // PAPER LINE 6
    const crypto::ec_scalar x_ip =
      hash_dataV_to_scalar(crypto::dataV{x, x, taux, mu, t});
    if (x_ip == rct::s_zero)
      {
        LOG_INFO("x_ip is 0, trying again");
        goto try_again;
      }

    // These are used in the inner product rounds
    const crypto::ec_scalar yinv = invert(y);
    const scalarV yinvpow = vector_exponents(yinv, MN);

    size_t nprime = MN;
    scalarV aprime = l;
    scalarV bprime = r;

    std::vector<crypto::ec_point> Gprime(G_V.begin(), std::next(G_V.begin(), MN));
    std::vector<crypto::ec_point> Hprime(H_V.begin(), std::next(H_V.begin(), MN));

    LR_V LR;

    std::optional<std::pair<scalarV, scalarV>> scale = split_vector(yinvpow);

    crypto::ec_scalar last_challenge = x_ip;

    while (nprime > 1)
      {
        // PAPER LINE 20
        nprime /= 2;

        // PAPER LINES 21-22
        crypto::ec_scalar cL = inner_product
          (
           std::span(aprime).subspan(0, nprime)
           , std::span(bprime).subspan(nprime, bprime.size() - nprime)
           );

        crypto::ec_scalar cR = inner_product
          (
           std::span(aprime).subspan(nprime, aprime.size() - nprime)
           , std::span(bprime).subspan(0, nprime)
           );

        // PAPER LINES 23-24
        const scalarS lbS = std::span(bprime).subspan(nprime);
        const scalarV lbV =
          scale
          ? hadamard_product(scale->first, lbS)
          : scalarV(lbS.begin(), lbS.end());

        const auto L = vector_commit_both
          (
           std::span(Gprime).subspan(nprime)
           , std::span(Hprime).subspan(0, nprime)
           , std::span(aprime).subspan(0, nprime)
           , lbV
           )
          + H_(cL * x_ip);

        const scalarS rbS = std::span(bprime).subspan(0, nprime);
        const scalarV rbV =
          scale
          ? hadamard_product(scale->second, rbS)
          : scalarV(rbS.begin(), rbS.end());

        const auto R = vector_commit_both
          (
           std::span(Gprime).subspan(0, nprime)
           , std::span(Hprime).subspan(nprime)
           , std::span(aprime).subspan(nprime)
           , rbV
           )
          + H_(cR * x_ip);

        LR.emplace_back(L, R);

        // PAPER LINES 25-27
        const auto challenge = hash_dataV_to_scalar
          (crypto::dataV{last_challenge, to_inv8(L), to_inv8(R)});

        last_challenge = challenge;

        if (challenge == rct::s_zero)
          {
            LOG_INFO("challenge is 0, trying again");
            goto try_again;
          }

        // PAPER LINES 29-30
        const crypto::ec_scalar winv = invert(challenge);
        if (nprime > 1)
          {
            const auto [gl, gr] = split_vector(Gprime);
            Gprime = vector_mult_both
              (
               gl
               , gr
               , vector_repeat(winv, gl.size())
               , vector_repeat(challenge, gl.size())
               );

            const auto [hl, hr] = split_vector(Hprime);
            Hprime =
              scale
              ? vector_mult_both
                (
                 hl
                 , hr
                 , vector_mult(scale->first, challenge)
                 , vector_mult(scale->second, winv)
                 )
              : vector_mult_both
                (
                 hl
                 , hr
                 , vector_repeat(challenge, hl.size())
                 , vector_repeat(winv, hl.size())
                 );
          }

        // PAPER LINES 33-34
        aprime = vector_addV
          (
           vector_mult
           (
            std::span(aprime).subspan(0, nprime)
            , challenge
            )
           , vector_mult
           (
            std::span(aprime).subspan(nprime, aprime.size() - nprime)
            , winv
            )
           );

        bprime = vector_addV
          (
           vector_mult
           (
            std::span(bprime).subspan(0, nprime)
            , winv
            )
           , vector_mult
           (
            std::span(bprime).subspan(nprime, bprime.size() - nprime)
            , challenge
            )
           );

        scale = {};
      }

    return Bulletproof
      {
        A, S, T1, T2, taux, mu, LR
        , aprime[0], bprime[0], t
      };
  }

}
