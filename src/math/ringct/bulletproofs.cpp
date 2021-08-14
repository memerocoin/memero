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

#include "vectorOps.hpp"
#include "rctOps.hpp"
#include "curveConstants.hpp"
#include "multiexp.hpp"

#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/string_tools.h"
#include "tools/common/varint.h"

#include "config/cryptonote.hpp"

#include <mutex>
#include <atomic>
#include <list>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "bulletproofs"

namespace rct
{

rct::key vector_exponent(const scalarS a, const scalarS b);

constexpr size_t maxN = 64;
constexpr size_t maxM = constant::BULLETPROOF_MAX_OUTPUTS;

const rct::scalarV oneN = vector_powers(rct::s_one, maxN);
const rct::scalarV twoN = vector_powers(rct::s_two, maxN);

std::array<rct::key, maxN*maxM> Hi;
std::array<rct::key, maxN*maxM> Gi;

const static rct::scalar ip12 = inner_product(oneN, twoN);

const auto multiexp = dummy;

rct::key get_exponent(const rct::key base, size_t idx)
{
  constexpr std::string_view domain_separator(config::HASH_KEY_BULLETPROOF_EXPONENT);
  const std::string hashed =
    std::string((const char*)base.data, sizeof(base)) + std::string(domain_separator) + tools::get_varint_data(idx);

  rct::key e = rct::hash_to_key_via_f2
    ( rct::hash2rct(crypto::sha3(epee::string_tools::string_to_blob(hashed))) );

  LOG_ERROR_AND_THROW_IF((e == rct::identity), "Exponent is point at infinity");
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

/* Given two scalar arrays, construct a vector commitment */
rct::key vector_exponent(const scalarS a, const scalarS b)
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
rct::key cross_vector_exponent8
(
 const size_t size
 , const std::span<key> A
 , const size_t Ao
 , const std::span<key> B
 , const size_t Bo
 , const scalarS a
 , const size_t ao
 , const scalarS b
 , const size_t bo
 , const std::optional<rct::scalarS> scale
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

  scalarV b_scalars(size);
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
keyV hadamard_fold
(
 const keyS v
 , const std::optional<rct::scalarS> scale
 , const rct::scalar a
 , const rct::scalar b
 )
{
  LOG_ERROR_AND_THROW_UNLESS((v.size() & 1) == 0, "Vector size should be even");
  const size_t sz = v.size() / 2;
  std::vector<key> out(sz);

  std::generate
    (
     out.begin()
     , out.end()
     , [n = 0, v, scale, a, b, sz] () mutable {
       const scalar x = scale
         ? a * (*scale)[n]
         : a;

       const size_t iy = sz + n;

       const scalar y = scale
         ? b * (*scale)[iy]
         : b;

       const auto r = multP(v[n], x) + multP(v[iy], y);
       n++;
       return r;
     }
     );

  return out;
}

/* Given a value v (0..2^N-1) and a mask gamma, construct a range proof */
Bulletproof bulletproof_MAKE(const rct::scalar sv, const rct::scalar gamma)
{
  return bulletproof_MAKE(std::vector<rct::scalar>{sv}, rct::scalarV{gamma});
}

Bulletproof bulletproof_MAKE(const uint64_t v, const rct::scalar gamma)
{
  return bulletproof_MAKE(std::vector<uint64_t>{v}, rct::scalarV{gamma});
}


/* Given a set of values v (0..2^N-1) and masks gamma, construct a range proof */
Bulletproof bulletproof_MAKE(const rct::scalarV sv, const rct::scalarV gamma)
{
  LOG_ERROR_AND_THROW_UNLESS(sv.size() == gamma.size(), "Incompatible sizes of sv and gamma");
  LOG_ERROR_AND_THROW_UNLESS(!sv.empty(), "sv is empty");
  for (const auto& sve: sv)
    LOG_ERROR_AND_THROW_UNLESS(is_reduced(sve), "Invalid sv input");
  for (const auto& g: gamma)
    LOG_ERROR_AND_THROW_UNLESS(is_reduced(g), "Invalid gamma input");

  init_exponents();

  constexpr size_t logN = 6; // log2(64)
  constexpr size_t N = 1<<logN;

  size_t M = 1;
  size_t logM = 0;

  while (M < std::min(maxM, sv.size())) {
    logM++;
    M = M << 1;
  }

  LOG_ERROR_AND_THROW_UNLESS(M <= maxM, "sv/gamma are too large");


  const size_t logMN = logM + logN;
  const size_t MN = M * N;

  rct::keyV V(sv.size());
  rct::scalarV aL(MN), aR(MN);
  rct::scalarV aL8(MN), aR8(MN);

  std::transform
    (
     sv.begin()
     , sv.end()
     , gamma.begin()
     , V.begin()
     , [](const auto& sv, const auto& g) {
       return rct::addScalarMult_G_H(g * s_inv_eight, sv * s_inv_eight);
     }
     );

  // PAPER LINES 41-42
  for (size_t j = 0; j < M; ++j)
  {
    for (size_t i = N; i-- > 0; )
    {
      if (j < sv.size() && (sv[j][i/8] & (((uint64_t)1)<<(i%8))))
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
  rct::scalar hash_carry = rct::hash_keys_to_scalar(V);

  // PAPER LINES 43-44
  const rct::scalar alpha = rct::skGen();
  const key A = vector_exponent(aL8, aR8) + rct::multG(alpha * rct::s_inv_eight);

  // PAPER LINES 45-47
  const rct::scalarV sL = rct::skvGen(MN);
  const rct::scalarV sR = rct::skvGen(MN);
  const rct::scalar rho = rct::skGen();
  const rct::key S = multP(vector_exponent(sL, sR) + rct::multG(rho), rct::s_inv_eight);

  // PAPER LINES 48-50
  const scalar y = hash_carry = hash_keys_to_scalar(std::array{s2k(hash_carry), A, S});
  if (y == rct::s_zero)
  {
    LOG_INFO("y is 0, trying again");
    goto try_again;
  }

  const scalar z = hash_carry = rct::hash_to_scalar(s2k(y));
  if (z == rct::s_zero)
  {
    LOG_INFO("z is 0, trying again");
    goto try_again;
  }

  // Polynomial construction by coefficients
  // PAPER LINES 70-71
  const rct::scalarV l0 = vector_subtract(aL, z);
  const rct::scalarS l1 = sL;

  rct::scalarV zero_twos(MN);
  const rct::scalarV zpow = vector_powers(z, M+2);
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
  const rct::scalarV r0 = vector_addV
    (
     hadamard(vector_add(aR, z), yMN)
     , zero_twos
     );

  const rct::scalarV r1 = hadamard(yMN, sR);

  // Polynomial construction before PAPER LINE 51
  const rct::scalar t1_1 = inner_product(l0, r1);
  const rct::scalar t1_2 = inner_product(l1, r0);
  const rct::scalar t1 = t1_1 + t1_2;
  const rct::scalar t2 = inner_product(l1, r1);

  // PAPER LINES 52-53
  const rct::scalar tau1 = rct::skGen();
  const rct::scalar tau2 = rct::skGen();

  const key T1 = multG(tau1 * rct::s_inv_eight) + multH(t1 * rct::s_inv_eight);
  const key T2 = multG(tau2 * rct::s_inv_eight) + multH(t2 * rct::s_inv_eight);

  // PAPER LINES 54-56
  const rct::scalar x = hash_carry = hash_keys_to_scalar
    (std::array{s2k(hash_carry), s2k(z), T1, T2});
  if (x == rct::s_zero)
  {
    LOG_INFO("x is 0, trying again");
    goto try_again;
  }

  // PAPER LINES 61-63
  const rct::scalar xsq = x * x;

  rct::scalar taux = tau1 * x + tau2 * xsq;
  for (size_t j = 1; j <= sv.size(); ++j)
  {
    LOG_ERROR_AND_THROW_UNLESS(j+1 < zpow.size(), "invalid zpow index");
    taux = zpow[j+1] * gamma[j-1] + taux;
  }

  const rct::scalar mu = x * rho + alpha;

  // PAPER LINES 58-60
  const rct::scalarV l = vector_addV(l0, vector_mult(l1, x));
  const rct::scalarV r = vector_addV(r0, vector_mult(r1, x));

  const rct::scalar t = inner_product(l, r);

  // PAPER LINE 6
  const rct::scalar x_ip = hash_carry =
    hash_keys_to_scalar(std::array{s2k(hash_carry), s2k(x), s2k(taux), s2k(mu), s2k(t)});
  if (x_ip == rct::s_zero)
  {
    LOG_INFO("x_ip is 0, trying again");
    goto try_again;
  }

  // These are used in the inner product rounds
  size_t nprime = MN;
  std::vector<key> Gprime(MN);
  std::vector<key> Hprime(MN);
  rct::scalarV aprime(MN);
  rct::scalarV bprime(MN);
  const rct::scalar yinv = invert(y);
  rct::scalarV yinvpow(MN);
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
  rct::keyV L(logMN);
  rct::keyV R(logMN);
  int round = 0;
  rct::scalarV w(logMN); // this is the challenge x in the inner product protocol

  std::optional<rct::scalarS> scale = yinvpow;
  while (nprime > 1)
  {
    // PAPER LINE 20
    nprime /= 2;

    // PAPER LINES 21-22
    rct::scalar cL = inner_product
      (
       std::span(aprime).subspan(0, nprime)
       , std::span(bprime).subspan(nprime, bprime.size() - nprime)
       );

    rct::scalar cR = inner_product
      (
       std::span(aprime).subspan(nprime, aprime.size() - nprime)
       , std::span(bprime).subspan(0, nprime)
       );

    // PAPER LINES 23-24
    L[round] = cross_vector_exponent8
      (nprime, Gprime, nprime, Hprime, 0, aprime, 0, bprime, nprime, scale)
      + multH(cL * x_ip * s_inv_eight);
    R[round] = cross_vector_exponent8
      (nprime, Gprime, 0, Hprime, nprime, aprime, nprime, bprime, 0, scale)
      + multH(cR * x_ip * s_inv_eight);

    // PAPER LINES 25-27
    w[round] = hash_carry = hash_keys_to_scalar(std::array{s2k(hash_carry), L[round], R[round]});
    if (w[round] == rct::s_zero)
    {
      LOG_INFO("w[round] is 0, trying again");
      goto try_again;
    }

    // PAPER LINES 29-30
    const rct::scalar winv = invert(w[round]);
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
    (
     V, A, S, T1, T2, taux, mu, L, R
     , aprime[0], bprime[0], t
     );
}

Bulletproof bulletproof_MAKE(const std::vector<uint64_t> v, const rct::scalarV gamma)
{
  LOG_ERROR_AND_THROW_UNLESS(v.size() == gamma.size(), "Incompatible sizes of v and gamma");

  // vG + gammaH
  rct::scalarV sv(v.size());
  for (size_t i = 0; i < v.size(); ++i)
  {
    sv[i] = rct::s_zero;
    sv[i].data[0] = v[i] & 255;
    sv[i].data[1] = (v[i] >> 8) & 255;
    sv[i].data[2] = (v[i] >> 16) & 255;
    sv[i].data[3] = (v[i] >> 24) & 255;
    sv[i].data[4] = (v[i] >> 32) & 255;
    sv[i].data[5] = (v[i] >> 40) & 255;
    sv[i].data[6] = (v[i] >> 48) & 255;
    sv[i].data[7] = (v[i] >> 56) & 255;
  }
  return bulletproof_MAKE(sv, gamma);
}

struct proof_data_t
{
  rct::scalar x, y, z, x_ip;
  std::vector<rct::scalar> w;
  size_t logM, inv_offset;
};

/* Given a range proof, determine if it is valid
 * This uses the method in PAPER LINES 95-105,
 *   weighted across multiple proofs in a batch
 */
bool bulletproof_VERIFY(const std::span<const Bulletproof> proofs)
{
  init_exponents();


  const size_t logN = 6;
  const size_t N = 1 << logN;

  // sanity and figure out which proof is longest
  size_t max_length = 0;
  size_t nV = 0;
  std::vector<proof_data_t> proof_data;
  proof_data.reserve(proofs.size());
  size_t inv_offset = 0;
  std::vector<rct::scalar> to_invert;
  to_invert.reserve(11 * proofs.size());
  size_t max_logM = 0;
  for (const Bulletproof& proof: proofs)
  {
    // check scalar range
    LOG_ERROR_AND_RETURN_UNLESS(is_reduced(proof.taux), false, "Input scalar not in range");

    LOG_ERROR_AND_RETURN_UNLESS(is_reduced(proof.a), false, "Input scalar not in range");
    LOG_ERROR_AND_RETURN_UNLESS(is_reduced(proof.b), false, "Input scalar not in range");
    LOG_ERROR_AND_RETURN_UNLESS(is_reduced(proof.t), false, "Input scalar not in range");

    LOG_ERROR_AND_RETURN_UNLESS(proof.V.size() >= 1, false, "V does not have at least one element");
    LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() == proof.R.size(), false, "Mismatched L and R sizes");
    LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() > 0, false, "Empty proof");

    max_length = std::max(max_length, proof.L.size());
    nV += proof.V.size();

    // Reconstruct the challenges
    proof_data_t pd;
    rct::scalar hash_carry = rct::hash_keys_to_scalar(proof.V);

    pd.y = hash_carry = hash_keys_to_scalar(std::array{s2k(hash_carry), proof.A, proof.S});
    LOG_ERROR_AND_RETURN_IF((pd.y == rct::s_zero), false, "y == 0");

    pd.z = hash_carry = rct::hash_to_scalar(s2k(pd.y));
    LOG_ERROR_AND_RETURN_IF((pd.z == rct::s_zero), false, "z == 0");

    pd.x = hash_carry =
      hash_keys_to_scalar(std::array{s2k(hash_carry), s2k(pd.z), proof.T1, proof.T2});
    LOG_ERROR_AND_RETURN_IF((pd.x == rct::s_zero), false, "x == 0");

    pd.x_ip = hash_carry =
      hash_keys_to_scalar
      (
       std::array
       {
         s2k(hash_carry)
         , s2k(pd.x)
         , s2k(proof.taux)
         , s2k(proof.mu)
         , s2k(proof.t)
       });
    LOG_ERROR_AND_RETURN_IF((pd.x_ip == rct::s_zero), false, "x_ip == 0");

    size_t M;
    for (pd.logM = 0; (M = 1<<pd.logM) <= maxM && M < proof.V.size(); ++pd.logM);
    LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() == 6+pd.logM, false, "Proof is not the expected size");

    max_logM = std::max(pd.logM, max_logM);

    const size_t rounds = pd.logM + logN;
    LOG_ERROR_AND_RETURN_UNLESS(rounds > 0, false, "Zero rounds");

    // The inner product challenges are computed per round
    for (size_t i = 0; i < rounds; ++i)
    {
      const auto pd_w = hash_carry =
        hash_keys_to_scalar(std::array{s2k(hash_carry), proof.L[i], proof.R[i]});
      LOG_ERROR_AND_RETURN_IF((pd_w == rct::s_zero), false, "pd_w[i] == 0");
      pd.w.push_back(pd_w);

      to_invert.push_back(pd_w);
    }

    pd.inv_offset = inv_offset;
    to_invert.push_back(pd.y);

    proof_data.push_back(pd);

    inv_offset += rounds + 1;
  }
  LOG_ERROR_AND_RETURN_UNLESS(max_length < 32, false, "At least one proof is too large");
  size_t maxMN = 1u << max_length;

  std::vector<MultiexpData> multiexp_data;
  multiexp_data.reserve(nV + (2 * (max_logM + logN) + 4) * proofs.size() + 2 * maxMN);

  const scalarV inverses = invertV(to_invert);

  // setup weighted aggregates
  // accumulator
  rct::scalar z1 = rct::s_zero;
  rct::scalar z3 = rct::s_zero;
  rct::scalarV m_z4(maxMN, rct::s_zero), m_z5(maxMN, rct::s_zero);
  rct::scalar y0 = rct::s_zero, y1 = rct::s_zero;

  int proof_data_index = 0;

  for (const Bulletproof& proof: proofs)
  {
    const proof_data_t &pd = proof_data[proof_data_index++];
    LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() == 6+pd.logM, false, "Proof is not the expected size");

    const size_t rounds = pd.logM+logN;
    const rct::scalarS winv = std::span(inverses).subspan(pd.inv_offset);
    const rct::scalar yinv = inverses[pd.inv_offset + rounds];

    const rct::scalar weight_y = rct::skGen();
    const rct::scalar weight_z = rct::skGen();

    for (size_t i = 0; i < rounds; ++i)
    {
      multiexp_data.emplace_back(pd.w[i] * pd.w[i] * weight_z, multPoint8(proof.L[i]));
      multiexp_data.emplace_back(winv[i] * winv[i] * weight_z, multPoint8(proof.R[i]));
    }


    const size_t M = 1 << pd.logM;
    const size_t MN = M*N;

    const rct::scalarV zpow = vector_powers(pd.z, M+3);

    std::transform
      (
       proof.V.begin()
       , proof.V.end()
       , std::next(std::next(zpow.begin()))
       , std::back_inserter(multiexp_data)
       , [weight_y](const auto& x, const auto& y) -> MultiexpData {
         return {y * weight_y, multPoint8(x)};
       }
       );

    multiexp_data.emplace_back(pd.x * weight_y, multPoint8(proof.T1));
    multiexp_data.emplace_back(pd.x * pd.x * weight_y, multPoint8(proof.T2));
    multiexp_data.emplace_back(weight_z, multPoint8(proof.A));
    multiexp_data.emplace_back(pd.x * weight_z, multPoint8(proof.S));

    // Compute the number of rounds for the inner product
    LOG_ERROR_AND_RETURN_UNLESS(rounds > 0, false, "Zero rounds");


    // precalc
    rct::scalarV w_cache(1<<rounds);
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
    // rct::scalar yinvpow = rct::s_one;
    // rct::scalar ypow = rct::s_one;

    const scalarV c_z5 = m_z5;
    std::generate_n
      (
       m_z5.begin()
       , MN
       , [i = 0, yinvpow = s_one, ypow = s_one
          , zpow, yinv, pd, weight_z, proof, w_cache, MN, c_z5
          ] () mutable -> scalar {
         // Convert the index to binary IN REVERSE and construct the scalar exponent

         LOG_ERROR_AND_THROW_UNLESS(2+i/N < zpow.size(), "invalid zpow index");
         LOG_ERROR_AND_THROW_UNLESS(i%N < twoN.size(), "invalid twoN index");

         const auto zpowTwoN = zpow[2+i/N] * twoN[i%N];

         const scalar h_scalar =
           proof.b * yinvpow * w_cache[(~i) & (MN-1)]
           - (pd.z * ypow + zpowTwoN) * yinvpow ;


         yinvpow = yinvpow * yinv;
         ypow = ypow * pd.y;

         const scalar r = c_z5[i] - h_scalar * weight_z;
         i++;
         return r;
       }
       );

    std::transform
      (
       m_z4.begin()
       , std::next(m_z4.begin(), MN)
       , w_cache.begin()
       , m_z4.begin()
       , [proof, pd, weight_z](const auto& z4, const auto& cache) {
         const scalar g_scalar = proof.a * cache + pd.z;
         return z4 - g_scalar * weight_z;
       }
       );


    // collect
    const rct::scalar ip1y = vector_power_sum(pd.y, MN);
    rct::scalar k = s_zero - zpow[2] * ip1y;
    for (size_t j = 1; j <= M; ++j)
    {
      LOG_ERROR_AND_RETURN_UNLESS(j+2 < zpow.size(), false, "invalid zpow index");
      k = k - zpow[j+2] * ip12;
    }

    y0 = y0 - proof.taux * weight_y;
    y1 = y1 + (proof.t - (pd.z * ip1y + k)) * weight_y;
    z1 = z1 + proof.mu * weight_z;
    z3 = z3 + (proof.t - proof.a * proof.b) * pd.x_ip * weight_z;
  }

  // now check all proofs at once
  multiexp_data.emplace_back(y0 - z1, rct::G);
  multiexp_data.emplace_back(z3 - y1, rct::H);

  std::transform
    (
     m_z4.begin()
     , m_z4.end()
     , std::begin(Gi)
     , std::back_inserter(multiexp_data)
     , [](const auto& s, const auto& p) -> MultiexpData { return {s, p}; }
     );

  std::transform
    (
     m_z5.begin()
     , m_z5.end()
     , std::begin(Hi)
     , std::back_inserter(multiexp_data)
     , [](const auto& s, const auto& p) -> MultiexpData { return {s, p}; }
     );

  if (multiexp(multiexp_data) != rct::identity)
  {
    LOG_ERROR("Verification failure");
    return false;
  }
  return true;
}

bool bulletproof_VERIFY(const Bulletproof proof)
{
  return bulletproof_VERIFY(std::array{proof});
}

}
