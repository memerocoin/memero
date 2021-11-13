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

#include "bulletproofs.hpp"

#include "math/ringct/functional/vectorOps.hpp"
#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/functional/curveConstants.hpp"
#include "math/ringct/functional/multi_exponentiation.hpp"
#include "math/crypto/controller/keyGen.hpp"

#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/string_tools.h"
#include "tools/common/varint.h"

#include "config/cryptonote.hpp"

#include <mutex>
#include <atomic>
#include <list>
#include <numeric>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "bulletproofs"

namespace rct
{

rct::rct_point vector_exponent(const rct_scalarS a, const rct_scalarS b);

constexpr size_t maxN = 64;
constexpr size_t maxM = constant::BULLETPROOF_MAX_OUTPUTS;

const rct::rct_scalarV oneN = vector_powers(rct::s_one, maxN);
const rct::rct_scalarV twoN = vector_powers(rct::s_two, maxN);

std::array<rct::rct_point, maxN*maxM> Hi;
std::array<rct::rct_point, maxN*maxM> Gi;

const static rct::rct_scalar ip12 = inner_product(oneN, twoN);

const auto multiexp = dummy;

rct::rct_point get_exponent(const rct::rct_point base, size_t idx)
{
  constexpr std::string_view domain_separator = config::HASH_KEY_BULLETPROOF_EXPONENT;
  const std::string hashed =
    epee::string_tools::blob_to_string(base.data) + std::string(domain_separator) + tools::get_varint_data(idx);

  rct::rct_point e = rct::hash_to_point_via_field
    ( crypto::h2d(crypto::sha3(epee::string_tools::string_to_blob(hashed))) );

  LOG_ERROR_AND_THROW_IF((e == crypto::identity), "Exponent is point at infinity");
  return e;
}

std::atomic<bool> init_done(false);
std::mutex init_mutex;

void init_exponents()
{
  if (!init_done) {
    std::lock_guard<std::mutex> lock(init_mutex);
    std::generate
      (
       Hi.begin()
       , Hi.end()
       , [i = 0] () mutable {
         const auto r = get_exponent(rct::H, i * 2);
         i++;
         return r;
       }
       );

    std::generate
      (
       Gi.begin()
       , Gi.end()
       , [i = 0] () mutable {
         const auto r = get_exponent(rct::H, i * 2 + 1);
         i++;
         return r;
       }
       );

    init_done = true;
  }
}

/* Given two rct_scalar arrays, construct a vector commitment */
rct::rct_point vector_exponent(const rct_scalarS a, const rct_scalarS b)
{
  LOG_ERROR_AND_THROW_UNLESS(a.size() == b.size(), "Incompatible sizes of a and b");
  LOG_ERROR_AND_THROW_UNLESS(a.size() <= maxN*maxM, "Incompatible sizes of a and maxN");

  std::vector<MultiexpData> multiexp_data;
  multiexp_data.reserve(a.size()*2);
  std::transform
    (
     a.begin()
     , a.end()
     , Gi.begin()
     , std::back_inserter(multiexp_data)
     , [](const auto& s, const auto& p) -> MultiexpData { return {s, p}; }
     );

  std::transform
    (
     b.begin()
     , b.end()
     , Hi.begin()
     , std::back_inserter(multiexp_data)
     , [](const auto& s, const auto& p) -> MultiexpData { return {s, p}; }
     );
  return multiexp(multiexp_data);
}

/* Compute a custom vector-scalar commitment */
rct::rct_point cross_vector_exponent8
(
 const size_t size
 , const std::span<rct_point> A
 , const size_t Ao
 , const std::span<rct_point> B
 , const size_t Bo
 , const rct_scalarS a
 , const size_t ao
 , const rct_scalarS b
 , const size_t bo
 , const std::optional<rct::rct_scalarS> scale
 )
{
  LOG_ERROR_AND_THROW_UNLESS(size + Ao <= A.size(), "Incompatible size for A");
  LOG_ERROR_AND_THROW_UNLESS(size + Bo <= B.size(), "Incompatible size for B");
  LOG_ERROR_AND_THROW_UNLESS(size + ao <= a.size(), "Incompatible size for a");
  LOG_ERROR_AND_THROW_UNLESS(size + bo <= b.size(), "Incompatible size for b");
  LOG_ERROR_AND_THROW_UNLESS(size <= maxN*maxM, "size is too large");
  LOG_ERROR_AND_THROW_UNLESS(!scale || size == scale->size() / 2, "Incompatible size for scale");

  std::vector<MultiexpData> multiexp_data;
  multiexp_data.reserve(size*2);

  std::transform
    (
     std::next(a.begin(), ao)
     , std::next(a.begin(), ao + size)
     , std::next(A.begin(), Ao)
     , std::back_inserter(multiexp_data)
     , [](const auto& s, const auto& p) -> MultiexpData { return {s * s_inv_eight, p}; }
     );

  rct_scalarV b_scalars(size);
  std::generate
    (

     b_scalars.begin()
     , b_scalars.end()
     , [i = 0, b, bo, scale, Bo]() mutable {
       const auto b_scaled = scale ? b[bo+i] * (*scale)[Bo+i] : b[bo+i];
       i++;
       return b_scaled;
     }
     );

  std::transform
    (
     b_scalars.begin()
     , b_scalars.end()
     , std::next(B.begin(), Bo)
     , std::back_inserter(multiexp_data)
     , [](const auto& s, const auto& p) -> MultiexpData { return {s * s_inv_eight, p}; }
     );

  return multiexp(multiexp_data);
}



/* folds a curvepoint array using a two way scaled Hadamard product */
rct_pointV hadamard_fold
(
 const rct_pointS v
 , const std::optional<rct::rct_scalarS> scale
 , const rct::rct_scalar a
 , const rct::rct_scalar b
 )
{
  LOG_ERROR_AND_THROW_UNLESS((v.size() & 1) == 0, "Vector size should be even");
  const size_t sz = v.size() / 2;
  std::vector<rct_point> out(sz);

  std::generate
    (
     out.begin()
     , out.end()
     , [n = 0, v, scale, a, b, sz] () mutable {
       const rct_scalar x = scale
         ? a * (*scale)[n]
         : a;

       const size_t iy = sz + n;

       const rct_scalar y = scale
         ? b * (*scale)[iy]
         : b;

       const auto r = (v[n] ^ x) + (v[iy] ^ y);
       n++;
       return r;
     }
     );

  return out;
}

constexpr std::pair<size_t, size_t> log2bound(const size_t x) {
  size_t y = 1;
  size_t _log = 0;

  while (y < x) {
    _log++;
    y = y << 1;
  }

  return {y, _log};
}

/* Given a set of values v (0..2^N-1) and masks gamma, construct a range proof */
Bulletproof bulletproof_MAKE(const std::vector<std::pair<uint64_t, rct_scalar>> xs)
{
  LOG_ERROR_AND_THROW_UNLESS(!xs.empty(), "Nothing to proof");

  for (const auto& [x,g]: xs) {
    LOG_ERROR_AND_THROW_UNLESS(is_reduced(g), "Invalid gamma input");
  }

  init_exponents();

  const auto [N, logN] = log2bound(maxN);
  const auto [M, logM] = log2bound(std::min(maxM, xs.size()));

  LOG_ERROR_AND_THROW_UNLESS(M <= maxM, "sv/gamma are too large");


  const size_t logMN = logM + logN;
  const size_t MN = M * N;

  rct::rct_pointV V(xs.size());
  rct::rct_scalarV aL(MN), aR(MN);
  rct::rct_scalarV aL8(MN), aR8(MN);

  std::transform
    (
     xs.begin()
     , xs.end()
     , V.begin()
     , [](const auto& x) {
       return rct::G_(x.second * s_inv_eight) + rct::H_(crypto::int_to_scalar(x.first) * s_inv_eight);
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
        aL8[j*N+i] = rct::s_inv_eight;
        aR[j*N+i] = aR8[j*N+i] = rct::s_zero;
      }
      else
      {
        aL[j*N+i] = aL8[j*N+i] = rct::s_zero;
        aR[j*N+i] = rct::s_minus_one;
        aR8[j*N+i] = rct::s_minus_inv_eight;
      }
    }
  }

try_again:
  crypto::dataV hash_dataV(V.size());
  std::copy(V.begin(), V.end(), hash_dataV.begin());
  rct::rct_scalar hash_carry = rct::hash_dataV_to_scalar(hash_dataV);

  // PAPER LINES 43-44
  const rct::rct_scalar alpha = crypto::scalarGen();
  const rct_point A = vector_exponent(aL8, aR8) + G_(alpha * rct::s_inv_eight);

  // PAPER LINES 45-47
  const rct::rct_scalarV sL = crypto::scalarVGen(MN);
  const rct::rct_scalarV sR = crypto::scalarVGen(MN);
  const rct::rct_scalar rho = crypto::scalarGen();
  const rct::rct_point S = (vector_exponent(sL, sR) + G_(rho)) ^ rct::s_inv_eight;

  // PAPER LINES 48-50
  const rct_scalar y = hash_carry = hash_dataV_to_scalar(crypto::dataV{hash_carry, A, S});
  if (y == rct::s_zero)
  {
    LOG_INFO("y is 0, trying again");
    goto try_again;
  }

  const rct_scalar z = hash_carry = rct::hash_to_scalar(y);
  if (z == rct::s_zero)
  {
    LOG_INFO("z is 0, trying again");
    goto try_again;
  }

  // Polynomial construction by coefficients
  // PAPER LINES 70-71
  const rct::rct_scalarV l0 = vector_subtract(aL, z);
  const rct::rct_scalarS l1 = sL;

  rct::rct_scalarV zero_twos(MN);
  const rct::rct_scalarV zpow = vector_powers(z, M+2);
  for (size_t j = 0; j < M; ++j)
  {
      for (size_t i = 0; i < N; ++i)
      {
          LOG_ERROR_AND_THROW_UNLESS(j+2 < zpow.size(), "invalid zpow index");
          LOG_ERROR_AND_THROW_UNLESS(i < twoN.size(), "invalid twoN index");
          zero_twos[j*N+i] = zpow[j+2] * twoN[i];
      }
  }

  const auto yMN = vector_powers(y, MN);
  const rct::rct_scalarV r0 = vector_addV
    (
     hadamard(vector_add(aR, z), yMN)
     , zero_twos
     );

  const rct::rct_scalarV r1 = hadamard(yMN, sR);

  // Polynomial construction before PAPER LINE 51
  const rct::rct_scalar t1_1 = inner_product(l0, r1);
  const rct::rct_scalar t1_2 = inner_product(l1, r0);
  const rct::rct_scalar t1 = t1_1 + t1_2;
  const rct::rct_scalar t2 = inner_product(l1, r1);

  // PAPER LINES 52-53
  const rct::rct_scalar tau1 = crypto::scalarGen();
  const rct::rct_scalar tau2 = crypto::scalarGen();

  const rct_point T1 = G_(tau1 * rct::s_inv_eight) + H_(t1 * rct::s_inv_eight);
  const rct_point T2 = G_(tau2 * rct::s_inv_eight) + H_(t2 * rct::s_inv_eight);

  // PAPER LINES 54-56
  const rct::rct_scalar x = hash_carry = hash_dataV_to_scalar
    (crypto::dataV{hash_carry, z, T1, T2});
  if (x == rct::s_zero)
  {
    LOG_INFO("x is 0, trying again");
    goto try_again;
  }

  // PAPER LINES 61-63
  const rct::rct_scalar xsq = x * x;

  rct::rct_scalar taux = tau1 * x + tau2 * xsq;
  for (size_t j = 1; j <= xs.size(); ++j)
  {
    LOG_ERROR_AND_THROW_UNLESS(j+1 < zpow.size(), "invalid zpow index");
    taux = zpow[j+1] * xs[j-1].second + taux;
  }

  const rct::rct_scalar mu = x * rho + alpha;

  // PAPER LINES 58-60
  const rct::rct_scalarV l = vector_addV(l0, vector_mult(l1, x));
  const rct::rct_scalarV r = vector_addV(r0, vector_mult(r1, x));

  const rct::rct_scalar t = inner_product(l, r);

  // PAPER LINE 6
  const rct::rct_scalar x_ip = hash_carry =
    hash_dataV_to_scalar(crypto::dataV{hash_carry, x, taux, mu, t});
  if (x_ip == rct::s_zero)
  {
    LOG_INFO("x_ip is 0, trying again");
    goto try_again;
  }

  // These are used in the inner product rounds
  size_t nprime = MN;
  std::vector<rct_point> Gprime(MN);
  std::vector<rct_point> Hprime(MN);
  rct::rct_scalarV aprime(MN);
  rct::rct_scalarV bprime(MN);
  const rct::rct_scalar yinv = invert(y);
  rct::rct_scalarV yinvpow(MN);
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
  rct::rct_pointV L(logMN);
  rct::rct_pointV R(logMN);
  int round = 0;
  rct::rct_scalarV w(logMN); // this is the challenge x in the inner product protocol

  std::optional<rct::rct_scalarS> scale = yinvpow;
  while (nprime > 1)
  {
    // PAPER LINE 20
    nprime /= 2;

    // PAPER LINES 21-22
    rct::rct_scalar cL = inner_product
      (
       std::span(aprime).subspan(0, nprime)
       , std::span(bprime).subspan(nprime, bprime.size() - nprime)
       );

    rct::rct_scalar cR = inner_product
      (
       std::span(aprime).subspan(nprime, aprime.size() - nprime)
       , std::span(bprime).subspan(0, nprime)
       );

    // PAPER LINES 23-24
    L[round] = cross_vector_exponent8
      (nprime, Gprime, nprime, Hprime, 0, aprime, 0, bprime, nprime, scale)
      + H_(cL * x_ip * s_inv_eight);
    R[round] = cross_vector_exponent8
      (nprime, Gprime, 0, Hprime, nprime, aprime, nprime, bprime, 0, scale)
      + H_(cR * x_ip * s_inv_eight);

    // PAPER LINES 25-27
    w[round] = hash_carry = hash_dataV_to_scalar(crypto::dataV{hash_carry, L[round], R[round]});
    if (w[round] == rct::s_zero)
    {
      LOG_INFO("w[round] is 0, trying again");
      goto try_again;
    }

    // PAPER LINES 29-30
    const rct::rct_scalar winv = invert(w[round]);
    if (nprime > 1)
    {
      Gprime = hadamard_fold(Gprime, {}, winv, w[round]);
      Hprime = hadamard_fold(Hprime, scale, w[round], winv);
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
     V, A, S, T1, T2, taux, mu, zipLR(L, R)
     , aprime[0], bprime[0], t
     };
}

struct proof_data_t
{
  rct::rct_scalar x, y, z, x_ip;
  std::vector<rct::rct_scalar> w;
};

/* Given a range proof, determine if it is valid
 * This uses the method in PAPER LINES 95-105,
 *   weighted across multiple proofs in a batch
 */
bool bulletproof_VERIFY(const Bulletproof proof)
{
  init_exponents();

  // sanity and figure out which proof is longest
  std::vector<rct::rct_scalar> to_invert;
  to_invert.reserve(11);

  // STEP 1, fill proof_data

  LOG_ERROR_AND_RETURN_UNLESS(proof.V.size() >= 1, false, "V does not have at least one element");
  LOG_ERROR_AND_RETURN_UNLESS(proof.LR.size() > 0, false, "Empty proof");


  // Reconstruct the challenges
  crypto::dataV hash_dataV(proof.V.size());
  std::copy(proof.V.begin(), proof.V.end(), hash_dataV.begin());
  rct::rct_scalar hash_carry = rct::hash_dataV_to_scalar(hash_dataV);

  proof_data_t pd;
  pd.y = hash_carry = hash_dataV_to_scalar(crypto::dataV{hash_carry, proof.A, proof.S});
  LOG_ERROR_AND_RETURN_IF((pd.y == rct::s_zero), false, "y == 0");

  pd.z = hash_carry = rct::hash_to_scalar(pd.y);
  LOG_ERROR_AND_RETURN_IF((pd.z == rct::s_zero), false, "z == 0");

  pd.x = hash_carry =
    hash_dataV_to_scalar(crypto::dataV{hash_carry, pd.z, proof.T1, proof.T2});
  LOG_ERROR_AND_RETURN_IF((pd.x == rct::s_zero), false, "x == 0");

  pd.x_ip = hash_carry =
    hash_dataV_to_scalar
    (
      crypto::dataV
      {
        hash_carry
        , pd.x
        , proof.taux
        , proof.mu
        , proof.t
      });
  LOG_ERROR_AND_RETURN_IF((pd.x_ip == rct::s_zero), false, "x_ip == 0");

  constexpr size_t N = log2bound(maxN).first;
  constexpr size_t logN = log2bound(maxN).second;
  const auto [M, logM] = log2bound(std::min(maxM, proof.V.size()));

  const size_t rounds = logM + logN;
  LOG_ERROR_AND_RETURN_UNLESS(proof.LR.size() == rounds, false, "Proof is not the expected size");
  LOG_ERROR_AND_RETURN_UNLESS(proof.LR.size() < 32, false, "At least one proof is too large");

  // The inner product challenges are computed per round
  std::transform
    (
     proof.LR.begin()
     , proof.LR.end()
     , std::back_inserter(pd.w)
     , [hash_carry](const auto& lr) mutable {
       const auto pd_w =
         hash_dataV_to_scalar(crypto::dataV{hash_carry, lr.first, lr.second});
       hash_carry = pd_w;
       return pd_w;
     }
     );

  const bool valid_pd_w = std::transform_reduce
    (
     pd.w.begin()
     , pd.w.end()
     , true
     , std::logical_and()
     , [](const auto& x) { return x != rct::s_zero; }
     );

  LOG_ERROR_AND_RETURN_UNLESS(valid_pd_w, false, "some pd_w[i] == 0");

  const size_t maxMN = 1u << proof.LR.size();

  // STEP 2, use proof_data
  std::vector<MultiexpData> multiexp_data;
  multiexp_data.reserve(proof.V.size() + (2 * (logM + logN) + 4) + 2 * maxMN);

  // setup weighted aggregates

  const rct::rct_scalarV winv = invertV(pd.w);
  const rct::rct_scalar yinv = invert(pd.y);

  const rct::rct_scalar weight_y = crypto::scalarGen();
  const rct::rct_scalar weight_z = crypto::scalarGen();

  std::transform
    (
     pd.w.begin()
     , pd.w.end()
     , proof.LR.begin()
     , std::back_inserter(multiexp_data)
     , [weight_z](const auto& w, const auto& lr) -> MultiexpData {
       return {w * w * weight_z * s_eight, lr.first};
     }
     );

  std::transform
    (
     winv.begin()
     , winv.end()
     , proof.LR.begin()
     , std::back_inserter(multiexp_data)
     , [weight_z](const auto& w, const auto& lr) -> MultiexpData {
       return {w * w * weight_z * s_eight, lr.second};
     }
     );

  const size_t MN = M*N;

  const rct::rct_scalarV zpow = vector_powers(pd.z, M+3);

  std::transform
    (
      proof.V.begin()
      , proof.V.end()
      , std::next(std::next(zpow.begin()))
      , std::back_inserter(multiexp_data)
      , [weight_y](const auto& x, const auto& y) -> MultiexpData {
        return {y * weight_y * s_eight, x};
      }
      );

  multiexp_data.emplace_back(pd.x * weight_y * s_eight, proof.T1);
  multiexp_data.emplace_back(pd.x * pd.x * weight_y * s_eight, proof.T2);
  multiexp_data.emplace_back(weight_z * s_eight, proof.A);
  multiexp_data.emplace_back(pd.x * weight_z * s_eight, proof.S);

  // Compute the number of rounds for the inner product

  // precalc
  rct::rct_scalarV w_cache(1<<rounds);
  w_cache[0] = winv[0];
  w_cache[1] = pd.w[0];
  for (size_t j = 1; j < rounds; ++j)
  {
    const size_t slots = 1<<(j+1);
    for (size_t s = slots; s-- > 0; --s)
    {
      w_cache[s] = w_cache[s/2] * pd.w[j];
      w_cache[s-1] = w_cache[s/2] * winv[j];
    }
  }

  // Compute the curvepoints from G[i] and H[i]
  rct::rct_scalarV z5_v(MN);
  std::generate
    (
      z5_v.begin()
      , z5_v.end()
      , [i = 0, yinvpow = s_one, ypow = s_one
        , zpow, yinv, pd, weight_z, proof, w_cache, MN
        ] () mutable -> rct_scalar {
        // Convert the index to binary IN REVERSE and construct the rct_scalar exponent

        LOG_ERROR_AND_THROW_UNLESS(2+i/N < zpow.size(), "invalid zpow index");
        LOG_ERROR_AND_THROW_UNLESS(i%N < twoN.size(), "invalid twoN index");

        const auto zpowTwoN = zpow[2+i/N] * twoN[i%N];

        const rct_scalar h_scalar =
          proof.b * yinvpow * w_cache[(~i) & (MN-1)]
          - (pd.z * ypow + zpowTwoN) * yinvpow ;


        yinvpow = yinvpow * yinv;
        ypow = ypow * pd.y;

        const rct_scalar r = s_zero - h_scalar * weight_z;
        i++;
        return r;
      }
      );

  rct::rct_scalarV z4_v(MN);
  std::transform
    (
      w_cache.begin()
      , std::next(w_cache.begin(), MN)
      , z4_v.begin()
      , [proof, pd, weight_z](const auto& cache) {
        const rct_scalar g_scalar = proof.a * cache + pd.z;
        return s_zero - g_scalar * weight_z;
      }
      );


  // collect
  const rct::rct_scalar ip1y = vector_power_sum(pd.y, MN);
  rct::rct_scalar k = s_zero - zpow[2] * ip1y;
  LOG_ERROR_AND_RETURN_UNLESS(M+2 < zpow.size(), false, "invalid zpow index");

  const auto zpow_it = std::next(zpow.begin(), 3);
  const rct_scalar k1 =
    std::reduce
    (
     zpow_it
     , std::next(zpow_it, M)
     , s_zero
     );

  k = k - k1 * ip12;


  const rct_scalar y0 = s_zero - proof.taux * weight_y;
  const rct_scalar y1 = (proof.t - (pd.z * ip1y + k)) * weight_y;
  const rct_scalar z1 = proof.mu * weight_z;
  const rct_scalar z3 = (proof.t - proof.a * proof.b) * pd.x_ip * weight_z;


  // now check all proofs at once
  multiexp_data.emplace_back(s_one, G_(y0 - z1));
  multiexp_data.emplace_back(z3 - y1, rct::H);

  std::transform
    (
     z4_v.begin()
     , z4_v.end()
     , std::begin(Gi)
     , std::back_inserter(multiexp_data)
     , [](const auto& s, const auto& p) -> MultiexpData { return {s, p}; }
     );

  std::transform
    (
     z5_v.begin()
     , z5_v.end()
     , std::begin(Hi)
     , std::back_inserter(multiexp_data)
     , [](const auto& s, const auto& p) -> MultiexpData { return {s, p}; }
     );

  if (multiexp(multiexp_data) != crypto::identity)
  {
    LOG_ERROR("Verification failure");
    return false;
  }
  return true;
}

}
