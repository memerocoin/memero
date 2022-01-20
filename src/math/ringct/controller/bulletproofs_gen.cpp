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

  std::array<crypto::ec_point, bit_width * max_outputs> Hi;
  std::array<crypto::ec_point, bit_width * max_outputs> Gi;

  crypto::ec_point get_generator(const crypto::ec_point base, size_t idx)
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

  crypto::ec_point get_generator_G(const size_t idx) {
    return get_generator(H, idx * 2);
  }

  crypto::ec_point get_generator_H(const size_t idx) {
    return get_generator(H, idx * 2 + 1);
  }

  std::atomic<bool> init_done(false);
  std::mutex init_mutex;

  void init_generators()
  {
    if (!init_done) {
      std::lock_guard<std::mutex> lock(init_mutex);
      std::generate
        (
         Hi.begin()
         , Hi.end()
         , [i = 0] () mutable {
           const auto r = get_generator_G(i);
           i++;
           return r;
         }
         );

      std::generate
        (
         Gi.begin()
         , Gi.end()
         , [i = 0] () mutable {
           const auto r = get_generator_H(i);
           i++;
           return r;
         }
         );

      init_done = true;
    }
  }


  /* Given two crypto::ec_scalar arrays, construct a vector commitment */
  crypto::ec_point commit_vectors_with_generators_G_H
  (
   const scalarS a
   , const scalarS b
   )
  {
    LOG_ERROR_AND_THROW_UNLESS
      (a.size() == b.size(), "Incompatible sizes of a and b");

    LOG_ERROR_AND_THROW_UNLESS
      (a.size() <= max_vector_length, "vector size too big");

    return vector_commit_both(a, Gi, b, Hi);
  }

  /* Compute a custom vector-scalar commitment */
  crypto::ec_point split_vector_commit
  (
   const size_t size
   , const std::span<crypto::ec_point> A
   , const size_t Ao
   , const std::span<crypto::ec_point> B
   , const size_t Bo
   , const scalarS a
   , const size_t ao
   , const scalarS b
   , const size_t bo
   , const std::optional<scalarS> scale
   )
  {
    LOG_ERROR_AND_THROW_UNLESS(size + Ao <= A.size(), "Incompatible size for A");
    LOG_ERROR_AND_THROW_UNLESS(size + Bo <= B.size(), "Incompatible size for B");
    LOG_ERROR_AND_THROW_UNLESS(size + ao <= a.size(), "Incompatible size for a");
    LOG_ERROR_AND_THROW_UNLESS(size + bo <= b.size(), "Incompatible size for b");
    LOG_ERROR_AND_THROW_UNLESS(size <= max_vector_length, "size is too large");
    LOG_ERROR_AND_THROW_UNLESS
      (!scale || size == scale->size() / 2, "Incompatible size for scale");

    const scalarS b0 = b.subspan(bo, size);

    const scalarV b_scalars =
      scale ? hadamard_product(b0, scale->subspan(Bo, size)) :
      scalarV(b0.begin(), b0.end()) ;

    return
      vector_commit_both
      (
       a.subspan(ao, size)
       , A.subspan(Ao)
       , b_scalars
       , B.subspan(Bo)
       );
  }


  pointV vector_mult_both
  (
   const pointS vl
   , const pointS vr
   , const std::optional<std::pair<scalarS, scalarS>> scale
   , const crypto::ec_scalar a
   , const crypto::ec_scalar b
   )
  {
    LOG_ERROR_AND_THROW_UNLESS(vl.size() == vr.size(), "Vector size should be even");

    const size_t sz = vl.size();

    scalarV scaled_a;
    if (scale) {
      scaled_a = vector_mult(scale->first, a);
    } else {
      std::generate_n(std::back_inserter(scaled_a), sz, [a](){ return a; });
    }

    scalarV scaled_b;
    if (scale) {
      scaled_b = vector_mult(scale->second, b);
    } else {
      std::generate_n(std::back_inserter(scaled_b), sz, [b](){ return b; });
    }

    const pointV l = vector_multV(scaled_a, vl);
    const pointV r = vector_multV(scaled_b, vr);

    return vector_addV(l, r);
  }

  pointV split_vector_mult
  (
   const pointS v
   , const std::optional<scalarS> scale
   , const crypto::ec_scalar a
   , const crypto::ec_scalar b
   )
  {
    LOG_ERROR_AND_THROW_UNLESS((v.size() & 1) == 0, "Vector size should be even");
    const size_t sz = v.size() / 2;

    const auto [vl, vr] = split_vector(v);

    if (scale) {
      const auto s = *scale;
      LOG_ERROR_AND_THROW_UNLESS
        ((s.size() & 1) == 0, "Scale vectgor size should be even");

      const auto [sl, sr] = split_vector(s);
      return vector_mult_both(vl, vr, {{sl, sr}}, a, b);

    } else {
      return vector_mult_both(vl, vr, {}, a, b);
    }
  }

  crypto::ec_point split_vector_commit
  (
   const pointS v
   , const std::optional<scalarS> scale
   , const crypto::ec_scalar a
   , const crypto::ec_scalar b
   ) {
    LOG_ERROR_AND_THROW_UNLESS((v.size() & 1) == 0, "Vector size should be even");
    const auto xs = split_vector_mult(v, scale, a, b);
    
    return std::reduce(xs.begin(), xs.end(), crypto::identity);
  }

  /* Given a set of values v (0..2^N-1) and masks gamma, construct a range proof */
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



    const size_t logMN = logM + logN;
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
      commit_vectors_with_generators_G_H(aL, aR) + G_(alpha);

    // PAPER LINES 45-47
    const scalarV sL = crypto::randomScalars(MN);
    const scalarV sR = crypto::randomScalars(MN);
    const crypto::ec_scalar rho = crypto::randomScalar();
    const crypto::ec_point S =
      commit_vectors_with_generators_G_H(sL, sR) + G_(rho);

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

    const crypto::ec_scalar taux1 =
      std::transform_reduce
      (
       xs.begin()
       , xs.end()
       , std::next(zpow.begin(), 2)
       , s_zero
       , std::plus()
       , [](const auto&x, const auto& z) {
         return z * x.second;
       }
       );

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
    size_t nprime = MN;
    std::vector<crypto::ec_point> Gprime(MN);
    std::vector<crypto::ec_point> Hprime(MN);
    scalarV aprime(MN);
    scalarV bprime(MN);
    const crypto::ec_scalar yinv = invert(y);
    scalarV yinvpow(MN);
    yinvpow[0] = rct::s_one;
    yinvpow[1] = yinv;
    for (size_t i = 0; i < MN; ++i)
      {
        Gprime[i] = Gi[i];
        Hprime[i] = Hi[i];
        if (i > 1)
          yinvpow[i] = yinvpow[i-1] * yinv;
        aprime[i] = l[i];
        bprime[i] = r[i];
      }
    LR_V LR(logMN);
    int round = 0;
    scalarV w(logMN); // this is the challenge x in the inner product protocol

    std::optional<scalarS> scale = yinvpow;

    crypto::ec_scalar last_hash = x_ip;

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

  // crypto::ec_point split_vector_commit
  // (
  //  const size_t size
  //  , const std::span<crypto::ec_point> A
  //  , const size_t Ao
  //  , const std::span<crypto::ec_point> B
  //  , const size_t Bo
  //  , const scalarS a
  //  , const size_t ao
  //  , const scalarS b
  //  , const size_t bo
  //  , const std::optional<scalarS> scale

        const auto L = split_vector_commit
          (nprime, Gprime, nprime, Hprime, 0, aprime, 0, bprime, nprime, scale)
          + H_(cL * x_ip);
        const auto R = split_vector_commit
          (nprime, Gprime, 0, Hprime, nprime, aprime, nprime, bprime, 0, scale)
          + H_(cR * x_ip);

        LR[round] = {L, R};

        // PAPER LINES 25-27
        w[round] = hash_dataV_to_scalar
          (crypto::dataV{last_hash, to_inv8(L), to_inv8(R)});

        last_hash = w[round];

        if (w[round] == rct::s_zero)
          {
            LOG_INFO("w[round] is 0, trying again");
            goto try_again;
          }

        // PAPER LINES 29-30
        const crypto::ec_scalar winv = invert(w[round]);
        if (nprime > 1)
          {
            Gprime = split_vector_mult(Gprime, {}, winv, w[round]);
            Hprime = split_vector_mult(Hprime, scale, w[round], winv);
          }

        // PAPER LINES 33-34
        aprime = vector_addV
          (
           vector_mult
           (
            std::span(aprime).subspan(0, nprime)
            , w[round]
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
            , w[round]
            )
           );

        scale = {};
        ++round;
      }

    return Bulletproof
      {
        A, S, T1, T2, taux, mu, LR
        , aprime[0], bprime[0], t
      };
  }

}
