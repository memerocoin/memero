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

#include "rctOps.hpp"
#include "curveConstants.hpp"
#include "multiexp.hpp"

extern "C"
{
#include "math/crypto/crypto-ops.h"
}

#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/string_tools.h"
#include "tools/common/varint.h"


#include "config/cryptonote.hpp"

#include <stdlib.h>
#include <mutex>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "bulletproofs"

namespace rct
{

rct::key vector_exponent(const scalarS a, const scalarS b);
rct::scalarV vector_powers(const rct::scalar x, const size_t n);
rct::scalar inner_product(const scalarS a, const scalarS b);

constexpr size_t maxN = 64;
constexpr size_t maxM = constant::BULLETPROOF_MAX_OUTPUTS;

const rct::scalarV oneN = vector_powers(rct::sone, maxN);
const rct::scalarV twoN = vector_powers(rct::stwo, maxN);

rct::key Hi[maxN*maxM], Gi[maxN*maxM];
ge_p3 Hi_p3[maxN*maxM], Gi_p3[maxN*maxM];

const static rct::scalar ip12 = inner_product(oneN, twoN);

std::mutex init_mutex;

const auto multiexp = pippenger;

inline bool is_reduced(const rct::scalar scalar)
{
  return sc_check(scalar.bytes) == 0;
}

rct::key get_exponent(const rct::key base, size_t idx)
{
  constexpr std::string_view domain_separator(config::HASH_KEY_BULLETPROOF_EXPONENT);
  const std::string hashed =
    std::string((const char*)base.bytes, sizeof(base)) + std::string(domain_separator) + tools::get_varint_data(idx);

  rct::key e;
  ge_p3 e_p3;
  rct::hash_to_p3
    (
     e_p3
     , rct::hash2rct(crypto::sha3(epee::string_tools::string_to_blob(hashed)))
     );
  ge_p3_tobytes(e.bytes, &e_p3);
  LOG_ERROR_AND_THROW_IF((e == rct::identity), "Exponent is point at infinity");
  return e;
}

void init_exponents()
{
  std::lock_guard<std::mutex> lock(init_mutex);

  static bool init_done = false;
  if (init_done)
    return;
  for (size_t i = 0; i < maxN*maxM; ++i)
  {
    Hi[i] = get_exponent(rct::H, i * 2);
    LOG_ERROR_AND_THROW_UNLESS(ge_frombytes_vartime(&Hi_p3[i], Hi[i].bytes) == 0, "ge_frombytes_vartime failed");
    Gi[i] = get_exponent(rct::H, i * 2 + 1);
    LOG_ERROR_AND_THROW_UNLESS(ge_frombytes_vartime(&Gi_p3[i], Gi[i].bytes) == 0, "ge_frombytes_vartime failed");
  }

  init_done = true;
}

/* Given two scalar arrays, construct a vector commitment */
rct::key vector_exponent(const scalarS a, const scalarS b)
{
  LOG_ERROR_AND_THROW_UNLESS(a.size() == b.size(), "Incompatible sizes of a and b");
  LOG_ERROR_AND_THROW_UNLESS(a.size() <= maxN*maxM, "Incompatible sizes of a and maxN");

  std::vector<MultiexpData> multiexp_data;
  multiexp_data.reserve(a.size()*2);
  for (size_t i = 0; i < a.size(); ++i)
  {
    multiexp_data.emplace_back(a[i], Gi_p3[i]);
    multiexp_data.emplace_back(b[i], Hi_p3[i]);
  }
  return multiexp(multiexp_data);
}

/* Compute a custom vector-scalar commitment */
rct::key cross_vector_exponent8
(
 const size_t size
 , const std::span<ge_p3> A
 , const size_t Ao
 , const std::span<ge_p3> B
 , const size_t Bo
 , const scalarS a
 , const size_t ao
 , const scalarS b
 , const size_t bo
 , const rct::scalarV *scale
 , const ge_p3 *extra_point
 , const rct::scalar *extra_scalar
 )
{
  LOG_ERROR_AND_THROW_UNLESS(size + Ao <= A.size(), "Incompatible size for A");
  LOG_ERROR_AND_THROW_UNLESS(size + Bo <= B.size(), "Incompatible size for B");
  LOG_ERROR_AND_THROW_UNLESS(size + ao <= a.size(), "Incompatible size for a");
  LOG_ERROR_AND_THROW_UNLESS(size + bo <= b.size(), "Incompatible size for b");
  LOG_ERROR_AND_THROW_UNLESS(size <= maxN*maxM, "size is too large");
  LOG_ERROR_AND_THROW_UNLESS(!scale || size == scale->size() / 2, "Incompatible size for scale");
  LOG_ERROR_AND_THROW_UNLESS(!!extra_point == !!extra_scalar, "only one of extra point/scalar present");

  std::vector<MultiexpData> multiexp_data;
  multiexp_data.resize(size*2 + (!!extra_point));
  for (size_t i = 0; i < size; ++i)
  {
    sc_mul(multiexp_data[i*2].scalar.bytes, a[ao+i].bytes, INV_EIGHT.bytes);
    multiexp_data[i*2].point = A[Ao+i];
    sc_mul(multiexp_data[i*2+1].scalar.bytes, b[bo+i].bytes, INV_EIGHT.bytes);
    if (scale)
      sc_mul(multiexp_data[i*2+1].scalar.bytes, multiexp_data[i*2+1].scalar.bytes, (*scale)[Bo+i].bytes);
    multiexp_data[i*2+1].point = B[Bo+i];
  }
  if (extra_point)
  {
    sc_mul(multiexp_data.back().scalar.bytes, extra_scalar->bytes, INV_EIGHT.bytes);
    multiexp_data.back().point = *extra_point;
  }
  return multiexp(multiexp_data);
}

/* Given a scalar, construct a vector of powers */
rct::scalarV vector_powers(const rct::scalar x, const size_t n)
{
  rct::scalarV res(n);
  if (n == 0)
    return res;
  res[0] = rct::sone;
  if (n == 1)
    return res;
  res[1] = x;
  for (size_t i = 2; i < n; ++i)
  {
    sc_mul(res[i].bytes, res[i-1].bytes, x.bytes);
  }
  return res;
}

/* Given a scalar, return the sum of its powers from 0 to n-1 */
rct::scalar vector_power_sum(const rct::scalar x_in, const size_t n_in)
{
  size_t n = n_in;

  if (n == 0)
    return rct::szero;
  rct::scalar res = rct::sone;
  if (n == 1)
    return res;

  const bool is_power_of_2 = (n & (n - 1)) == 0;
  rct::scalar x = x_in;

  if (is_power_of_2)
  {
    sc_add(res.bytes, res.bytes, x.bytes);
    while (n > 2)
    {
      sc_mul(x.bytes, x.bytes, x.bytes);
      sc_muladd(res.bytes, x.bytes, res.bytes, res.bytes);
      n /= 2;
    }
  }
  else
  {
    rct::scalar prev = x;
    for (size_t i = 1; i < n; ++i)
    {
      if (i > 1)
        sc_mul(prev.bytes, prev.bytes, x.bytes);
      sc_add(res.bytes, res.bytes, prev.bytes);
    }
  }

  return res;
}

/* Given two scalar arrays, construct the inner product */
rct::scalar inner_product(const scalarS a, const scalarS b)
{
  LOG_ERROR_AND_THROW_UNLESS(a.size() == b.size(), "Incompatible sizes of a and b");
  rct::scalar res = rct::szero;
  for (size_t i = 0; i < a.size(); ++i)
  {
    sc_muladd(res.bytes, a[i].bytes, b[i].bytes, res.bytes);
  }
  return res;
}

/* Given two scalar arrays, construct the Hadamard product */
rct::scalarV hadamard(const scalarS a, const scalarS b)
{
  LOG_ERROR_AND_THROW_UNLESS(a.size() == b.size(), "Incompatible sizes of a and b");
  rct::scalarV res(a.size());
  for (size_t i = 0; i < a.size(); ++i)
  {
    sc_mul(res[i].bytes, a[i].bytes, b[i].bytes);
  }
  return res;
}

/* folds a curvepoint array using a two way scaled Hadamard product */
void hadamard_fold(std::vector<ge_p3> &v, const rct::scalarV *scale, const rct::scalar a, const rct::scalar b)
{
  LOG_ERROR_AND_THROW_UNLESS((v.size() & 1) == 0, "Vector size should be even");
  const size_t sz = v.size() / 2;
  for (size_t n = 0; n < sz; ++n)
  {
    ge_dsmp c[2];
    ge_dsm_precomp(c[0], &v[n]);
    ge_dsm_precomp(c[1], &v[sz + n]);
    rct::scalar sa, sb;
    if (scale) sc_mul(sa.bytes, a.bytes, (*scale)[n].bytes); else sa = a;
    if (scale) sc_mul(sb.bytes, b.bytes, (*scale)[sz + n].bytes); else sb = b;
    ge_double_scalarmult_precomp_vartime2_p3(&v[n], sa.bytes, c[0], sb.bytes, c[1]);
  }
  v.resize(sz);
}

/* Add two vectors */
rct::scalarV vector_add(const scalarS a, const scalarS b)
{
  LOG_ERROR_AND_THROW_UNLESS(a.size() == b.size(), "Incompatible sizes of a and b");
  rct::scalarV res(a.size());
  for (size_t i = 0; i < a.size(); ++i)
  {
    sc_add(res[i].bytes, a[i].bytes, b[i].bytes);
  }
  return res;
}

/* Add a scalar to all elements of a vector */
rct::scalarV vector_add(const scalarS a, const rct::scalar b)
{
  rct::scalarV res(a.size());
  for (size_t i = 0; i < a.size(); ++i)
  {
    sc_add(res[i].bytes, a[i].bytes, b.bytes);
  }
  return res;
}

/* Subtract a scalar from all elements of a vector */
rct::scalarV vector_subtract(const scalarS a, const rct::scalar b)
{
  rct::scalarV res(a.size());
  for (size_t i = 0; i < a.size(); ++i)
  {
    sc_sub(res[i].bytes, a[i].bytes, b.bytes);
  }
  return res;
}

/* Multiply a scalar and a vector */
rct::scalarV vector_scalar(const scalarS a, const rct::scalar x)
{
  rct::scalarV res(a.size());
  for (size_t i = 0; i < a.size(); ++i)
  {
    sc_mul(res[i].bytes, a[i].bytes, x.bytes);
  }
  return res;
}

rct::scalar sm(const rct::scalar y_in, const int n_in, const rct::scalar x_in)
{
  int n = n_in;
  rct::scalar y = y_in;
  rct::scalar x = x_in;
  while (n--)
    sc_mul(y.bytes, y.bytes, y.bytes);
  sc_mul(y.bytes, y.bytes, x.bytes);
  return y;
}

/* Compute the inverse of a scalar, the clever way */
rct::scalar invert(const rct::scalar x)
{
  rct::scalar _1, _10, _100, _11, _101, _111, _1001, _1011, _1111;

  _1 = x;
  sc_mul(_10.bytes, _1.bytes, _1.bytes);
  sc_mul(_100.bytes, _10.bytes, _10.bytes);
  sc_mul(_11.bytes, _10.bytes, _1.bytes);
  sc_mul(_101.bytes, _10.bytes, _11.bytes);
  sc_mul(_111.bytes, _10.bytes, _101.bytes);
  sc_mul(_1001.bytes, _10.bytes, _111.bytes);
  sc_mul(_1011.bytes, _10.bytes, _1001.bytes);
  sc_mul(_1111.bytes, _100.bytes, _1011.bytes);

  rct::scalar inv;
  sc_mul(inv.bytes, _1111.bytes, _1.bytes);

  inv = sm(inv, 123 + 3, _101);
  inv = sm(inv, 2 + 2, _11);
  inv = sm(inv, 1 + 4, _1111);
  inv = sm(inv, 1 + 4, _1111);
  inv = sm(inv, 4, _1001);
  inv = sm(inv, 2, _11);
  inv = sm(inv, 1 + 4, _1111);
  inv = sm(inv, 1 + 3, _101);
  inv = sm(inv, 3 + 3, _101);
  inv = sm(inv, 3, _111);
  inv = sm(inv, 1 + 4, _1111);
  inv = sm(inv, 2 + 3, _111);
  inv = sm(inv, 2 + 2, _11);
  inv = sm(inv, 1 + 4, _1011);
  inv = sm(inv, 2 + 4, _1011);
  inv = sm(inv, 6 + 4, _1001);
  inv = sm(inv, 2 + 2, _11);
  inv = sm(inv, 3 + 2, _11);
  inv = sm(inv, 3 + 2, _11);
  inv = sm(inv, 1 + 4, _1001);
  inv = sm(inv, 1 + 3, _111);
  inv = sm(inv, 2 + 4, _1111);
  inv = sm(inv, 1 + 4, _1011);
  inv = sm(inv, 3, _101);
  inv = sm(inv, 2 + 4, _1111);
  inv = sm(inv, 3, _101);
  inv = sm(inv, 1 + 2, _11);

  return inv;
}

rct::scalarV invert(rct::scalarV x)
{
  rct::scalarV scratch;
  scratch.reserve(x.size());

  rct::scalar acc = rct::sone;
  for (size_t n = 0; n < x.size(); ++n)
  {
    scratch.push_back(acc);
    if (n == 0)
      acc = x[0];
    else
      sc_mul(acc.bytes, acc.bytes, x[n].bytes);
  }

  acc = invert(acc);

  rct::scalar tmp;
  for (int i = x.size(); i-- > 0; )
  {
    sc_mul(tmp.bytes, acc.bytes, x[i].bytes);
    sc_mul(x[i].bytes, acc.bytes, scratch[i].bytes);
    acc = tmp;
  }

  return x;
}

/* Compute the slice of a vector */
scalarS slice(const scalarS a, size_t start, size_t stop)
{
  LOG_ERROR_AND_THROW_UNLESS(start < a.size(), "Invalid start index");
  LOG_ERROR_AND_THROW_UNLESS(stop <= a.size(), "Invalid stop index");
  LOG_ERROR_AND_THROW_UNLESS(start < stop, "Invalid start/stop indices");
  return a.subspan(start, stop - start);
}

rct::key hash_cache_mash(rct::key& hash_cache, const rct::key mash0, const rct::key mash1)
{
  rct::keyV data = {
   hash_cache
   , mash0
   , mash1
  };
  hash_cache = rct::hash_keys_to_scalar(data);
  return hash_cache;
}

rct::key hash_cache_mash(rct::key& hash_cache, const rct::key mash0, const rct::key mash1, const rct::key mash2)
{
  rct::keyV data = {
    hash_cache
    , mash0
    , mash1
    , mash2
  };
  hash_cache = rct::hash_keys_to_scalar(data);
  return hash_cache;
}

rct::key hash_cache_mash(rct::key& hash_cache, const rct::key mash0, const rct::key mash1, const rct::key mash2, const rct::key mash3)
{
  rct::keyV data = {
    hash_cache
    , mash0
    , mash1
    , mash2
    , mash3
  };
  hash_cache = rct::hash_keys_to_scalar(data);
  return hash_cache;
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
  size_t M, logM;
  for (logM = 0; (M = 1<<logM) <= maxM && M < sv.size(); ++logM);
  LOG_ERROR_AND_THROW_UNLESS(M <= maxM, "sv/gamma are too large");
  const size_t logMN = logM + logN;
  const size_t MN = M * N;

  rct::keyV V(sv.size());
  rct::scalarV aL(MN), aR(MN);
  rct::scalarV aL8(MN), aR8(MN);
  rct::scalar tmp;
  rct::scalar tmp2;

  for (size_t i = 0; i < sv.size(); ++i)
  {
    rct::scalar gamma8, sv8;
    sc_mul(gamma8.bytes, gamma[i].bytes, INV_EIGHT.bytes);
    sc_mul(sv8.bytes, sv[i].bytes, INV_EIGHT.bytes);
    V[i] = rct::addScalarMult_G_H(gamma8, sv8);
  }

  // PAPER LINES 41-42
  for (size_t j = 0; j < M; ++j)
  {
    for (size_t i = N; i-- > 0; )
    {
      if (j < sv.size() && (sv[j][i/8] & (((uint64_t)1)<<(i%8))))
      {
        aL[j*N+i] = rct::sone;
        aL8[j*N+i] = rct::sinv_eight;
        aR[j*N+i] = aR8[j*N+i] = rct::szero;
      }
      else
      {
        aL[j*N+i] = aL8[j*N+i] = rct::szero;
        aR[j*N+i] = rct::sminus_one;
        aR8[j*N+i] = rct::sminus_inv_eight;
      }
    }
  }

try_again:
  rct::key hash_cache = rct::hash_keys_to_scalar(V);

  // PAPER LINES 43-44
  rct::scalar alpha = rct::skGen();
  rct::key ve = vector_exponent(aL8, aR8);
  rct::key A;
  sc_mul(tmp.bytes, alpha.bytes, INV_EIGHT.bytes);
  rct::addKeys(A, ve, rct::scalarmultBase(s2k(tmp)));

  // PAPER LINES 45-47
  rct::scalarV sL = rct::skvGen(MN), sR = rct::skvGen(MN);
  rct::scalar rho = rct::skGen();
  ve = vector_exponent(sL, sR);
  rct::key S;
  rct::addKeys(S, ve, rct::scalarmultBase(s2k(rho)));
  S = rct::scalarmultKey(S, INV_EIGHT);

  // PAPER LINES 48-50
  hash_cache_mash(hash_cache, A, S);
  rct::scalar y = k2s(hash_cache);
  if (y == rct::szero)
  {
    LOG_INFO("y is 0, trying again");
    goto try_again;
  }

  hash_cache = rct::hash_to_scalar(s2k(y));
  scalar z = k2s(hash_cache);
  if (z == rct::szero)
  {
    LOG_INFO("z is 0, trying again");
    goto try_again;
  }

  // Polynomial construction by coefficients
  // PAPER LINES 70-71
  rct::scalarV l0 = vector_subtract(aL, z);
  const rct::scalarV &l1 = sL;

  rct::scalarV zero_twos(MN);
  const rct::scalarV zpow = vector_powers(z, M+2);
  for (size_t j = 0; j < M; ++j)
  {
      for (size_t i = 0; i < N; ++i)
      {
          LOG_ERROR_AND_THROW_UNLESS(j+2 < zpow.size(), "invalid zpow index");
          LOG_ERROR_AND_THROW_UNLESS(i < twoN.size(), "invalid twoN index");
          sc_mul(zero_twos[j*N+i].bytes,zpow[j+2].bytes,twoN[i].bytes);
      }
  }

  rct::scalarV r0 = vector_add(aR, z);
  const auto yMN = vector_powers(y, MN);
  r0 = hadamard(r0, yMN);
  r0 = vector_add(r0, zero_twos);
  rct::scalarV r1 = hadamard(yMN, sR);

  // Polynomial construction before PAPER LINE 51
  rct::scalar t1_1 = inner_product(l0, r1);
  rct::scalar t1_2 = inner_product(l1, r0);
  rct::scalar t1;
  sc_add(t1.bytes, t1_1.bytes, t1_2.bytes);
  rct::scalar t2 = inner_product(l1, r1);

  // PAPER LINES 52-53
  rct::scalar tau1 = rct::skGen(), tau2 = rct::skGen();

  rct::key T1, T2;
  ge_p3 p3;
  sc_mul(tmp.bytes, t1.bytes, INV_EIGHT.bytes);
  sc_mul(tmp2.bytes, tau1.bytes, INV_EIGHT.bytes);
  ge_double_scalarmult_base_vartime_p3(&p3, tmp.bytes, &ge_p3_H, tmp2.bytes);
  ge_p3_tobytes(T1.bytes, &p3);
  sc_mul(tmp.bytes, t2.bytes, INV_EIGHT.bytes);
  sc_mul(tmp2.bytes, tau2.bytes, INV_EIGHT.bytes);
  ge_double_scalarmult_base_vartime_p3(&p3, tmp.bytes, &ge_p3_H, tmp2.bytes);
  ge_p3_tobytes(T2.bytes, &p3);

  // PAPER LINES 54-56
  rct::scalar x = k2s(hash_cache_mash(hash_cache, s2k(z), T1, T2));
  if (x == rct::szero)
  {
    LOG_INFO("x is 0, trying again");
    goto try_again;
  }

  // PAPER LINES 61-63
  rct::scalar taux;
  sc_mul(taux.bytes, tau1.bytes, x.bytes);
  rct::scalar xsq;
  sc_mul(xsq.bytes, x.bytes, x.bytes);
  sc_muladd(taux.bytes, tau2.bytes, xsq.bytes, taux.bytes);
  for (size_t j = 1; j <= sv.size(); ++j)
  {
    LOG_ERROR_AND_THROW_UNLESS(j+1 < zpow.size(), "invalid zpow index");
    sc_muladd(taux.bytes, zpow[j+1].bytes, gamma[j-1].bytes, taux.bytes);
  }
  rct::scalar mu;
  sc_muladd(mu.bytes, x.bytes, rho.bytes, alpha.bytes);

  // PAPER LINES 58-60
  rct::scalarV l = l0;
  l = vector_add(l, vector_scalar(l1, x));
  rct::scalarV r = r0;
  r = vector_add(r, vector_scalar(r1, x));

  rct::scalar t = inner_product(l, r);

  // PAPER LINE 6
  rct::scalar x_ip = k2s(hash_cache_mash(hash_cache, s2k(x), s2k(taux), s2k(mu), s2k(t)));
  if (x_ip == rct::szero)
  {
    LOG_INFO("x_ip is 0, trying again");
    goto try_again;
  }

  // These are used in the inner product rounds
  size_t nprime = MN;
  std::vector<ge_p3> Gprime(MN);
  std::vector<ge_p3> Hprime(MN);
  rct::scalarV aprime(MN);
  rct::scalarV bprime(MN);
  const rct::scalar yinv = invert(y);
  rct::scalarV yinvpow(MN);
  yinvpow[0] = rct::sone;
  yinvpow[1] = yinv;
  for (size_t i = 0; i < MN; ++i)
  {
    Gprime[i] = Gi_p3[i];
    Hprime[i] = Hi_p3[i];
    if (i > 1)
      sc_mul(yinvpow[i].bytes, yinvpow[i-1].bytes, yinv.bytes);
    aprime[i] = l[i];
    bprime[i] = r[i];
  }
  rct::keyV L(logMN);
  rct::keyV R(logMN);
  int round = 0;
  rct::scalarV w(logMN); // this is the challenge x in the inner product protocol

  const rct::scalarV *scale = &yinvpow;
  while (nprime > 1)
  {
    // PAPER LINE 20
    nprime /= 2;

    // PAPER LINES 21-22
    rct::scalar cL = inner_product(slice(aprime, 0, nprime), slice(bprime, nprime, bprime.size()));
    rct::scalar cR = inner_product(slice(aprime, nprime, aprime.size()), slice(bprime, 0, nprime));

    // PAPER LINES 23-24
    sc_mul(tmp.bytes, cL.bytes, x_ip.bytes);
    L[round] = cross_vector_exponent8
      (nprime, Gprime, nprime, Hprime, 0, aprime, 0, bprime, nprime, scale, &ge_p3_H, &tmp);
    sc_mul(tmp.bytes, cR.bytes, x_ip.bytes);
    R[round] = cross_vector_exponent8
      (nprime, Gprime, 0, Hprime, nprime, aprime, nprime, bprime, 0, scale, &ge_p3_H, &tmp);

    // PAPER LINES 25-27
    w[round] = k2s(hash_cache_mash(hash_cache, L[round], R[round]));
    if (w[round] == rct::szero)
    {
      LOG_INFO("w[round] is 0, trying again");
      goto try_again;
    }

    // PAPER LINES 29-30
    const rct::scalar winv = invert(w[round]);
    if (nprime > 1)
    {
      hadamard_fold(Gprime, NULL, winv, w[round]);
      hadamard_fold(Hprime, scale, w[round], winv);
    }

    // PAPER LINES 33-34
    aprime = vector_add(vector_scalar(slice(aprime, 0, nprime), w[round]), vector_scalar(slice(aprime, nprime, aprime.size()), winv));
    bprime = vector_add(vector_scalar(slice(bprime, 0, nprime), winv), vector_scalar(slice(bprime, nprime, bprime.size()), w[round]));

    scale = NULL;
    ++round;
  }

  return Bulletproof
    (
     std::move(V), A, S, T1, T2, taux, mu, std::move(L), std::move(R)
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
    sv[i] = rct::szero;
    sv[i].bytes[0] = v[i] & 255;
    sv[i].bytes[1] = (v[i] >> 8) & 255;
    sv[i].bytes[2] = (v[i] >> 16) & 255;
    sv[i].bytes[3] = (v[i] >> 24) & 255;
    sv[i].bytes[4] = (v[i] >> 32) & 255;
    sv[i].bytes[5] = (v[i] >> 40) & 255;
    sv[i].bytes[6] = (v[i] >> 48) & 255;
    sv[i].bytes[7] = (v[i] >> 56) & 255;
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
    proof_data.resize(proof_data.size() + 1);
    proof_data_t &pd = proof_data.back();
    rct::key hash_cache = rct::hash_keys_to_scalar(proof.V);

    pd.y = k2s(hash_cache_mash(hash_cache, proof.A, proof.S));
    LOG_ERROR_AND_RETURN_IF((pd.y == rct::szero), false, "y == 0");

    hash_cache = rct::hash_to_scalar(s2k(pd.y));
    pd.z = k2s(hash_cache);
    LOG_ERROR_AND_RETURN_IF((pd.z == rct::szero), false, "z == 0");

    pd.x = k2s(hash_cache_mash(hash_cache, s2k(pd.z), proof.T1, proof.T2));
    LOG_ERROR_AND_RETURN_IF((pd.x == rct::szero), false, "x == 0");

    pd.x_ip = k2s(hash_cache_mash(hash_cache, s2k(pd.x), s2k(proof.taux), s2k(proof.mu), s2k(proof.t)));
    LOG_ERROR_AND_RETURN_IF((pd.x_ip == rct::szero), false, "x_ip == 0");

    size_t M;
    for (pd.logM = 0; (M = 1<<pd.logM) <= maxM && M < proof.V.size(); ++pd.logM);
    LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() == 6+pd.logM, false, "Proof is not the expected size");
    max_logM = std::max(pd.logM, max_logM);

    const size_t rounds = pd.logM+logN;
    LOG_ERROR_AND_RETURN_UNLESS(rounds > 0, false, "Zero rounds");

    // The inner product challenges are computed per round
    pd.w.resize(rounds);
    for (size_t i = 0; i < rounds; ++i)
    {
      pd.w[i] = k2s(hash_cache_mash(hash_cache, proof.L[i], proof.R[i]));
      LOG_ERROR_AND_RETURN_IF((pd.w[i] == rct::szero), false, "w[i] == 0");
    }

    pd.inv_offset = inv_offset;
    for (size_t i = 0; i < rounds; ++i)
      to_invert.push_back(pd.w[i]);
    to_invert.push_back(pd.y);
    inv_offset += rounds + 1;
  }
  LOG_ERROR_AND_RETURN_UNLESS(max_length < 32, false, "At least one proof is too large");
  size_t maxMN = 1u << max_length;

  rct::scalar tmp;

  std::vector<MultiexpData> multiexp_data;
  multiexp_data.reserve(nV + (2 * (max_logM + logN) + 4) * proofs.size() + 2 * maxMN);
  multiexp_data.resize(2 * maxMN);

  const scalarV inverses = invert(to_invert);

  // setup weighted aggregates
  rct::scalar z1 = rct::szero;
  rct::scalar z3 = rct::szero;
  rct::scalarV m_z4(maxMN, rct::szero), m_z5(maxMN, rct::szero);
  rct::scalar m_y0 = rct::szero, y1 = rct::szero;
  int proof_data_index = 0;
  rct::scalarV w_cache;
  std::vector<ge_p3> proof8_V, proof8_L, proof8_R;
  for (const Bulletproof& proof: proofs)
  {
    const proof_data_t &pd = proof_data[proof_data_index++];

    LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() == 6+pd.logM, false, "Proof is not the expected size");
    const size_t M = 1 << pd.logM;
    const size_t MN = M*N;
    const rct::scalar weight_y = rct::skGen();
    const rct::scalar weight_z = rct::skGen();

    // pre-multiply some points by 8
    proof8_V.resize(proof.V.size()); for (size_t i = 0; i < proof.V.size(); ++i) rct::scalarmult8(proof8_V[i], proof.V[i]);
    proof8_L.resize(proof.L.size()); for (size_t i = 0; i < proof.L.size(); ++i) rct::scalarmult8(proof8_L[i], proof.L[i]);
    proof8_R.resize(proof.R.size()); for (size_t i = 0; i < proof.R.size(); ++i) rct::scalarmult8(proof8_R[i], proof.R[i]);
    ge_p3 proof8_T1;
    ge_p3 proof8_T2;
    ge_p3 proof8_S;
    ge_p3 proof8_A;
    rct::scalarmult8(proof8_T1, proof.T1);
    rct::scalarmult8(proof8_T2, proof.T2);
    rct::scalarmult8(proof8_S, proof.S);
    rct::scalarmult8(proof8_A, proof.A);

    sc_mulsub(m_y0.bytes, proof.taux.bytes, weight_y.bytes, m_y0.bytes);

    const rct::scalarV zpow = vector_powers(pd.z, M+3);

    rct::key k;
    const rct::scalar ip1y = vector_power_sum(pd.y, MN);
    sc_mulsub(k.bytes, zpow[2].bytes, ip1y.bytes, rct::zero.bytes);
    for (size_t j = 1; j <= M; ++j)
    {
      LOG_ERROR_AND_RETURN_UNLESS(j+2 < zpow.size(), false, "invalid zpow index");
      sc_mulsub(k.bytes, zpow[j+2].bytes, ip12.bytes, k.bytes);
    }

    sc_muladd(tmp.bytes, pd.z.bytes, ip1y.bytes, k.bytes);
    sc_sub(tmp.bytes, proof.t.bytes, tmp.bytes);
    sc_muladd(y1.bytes, tmp.bytes, weight_y.bytes, y1.bytes);
    for (size_t j = 0; j < proof8_V.size(); j++)
    {
      sc_mul(tmp.bytes, zpow[j+2].bytes, weight_y.bytes);
      multiexp_data.emplace_back(tmp, proof8_V[j]);
    }
    sc_mul(tmp.bytes, pd.x.bytes, weight_y.bytes);
    multiexp_data.emplace_back(tmp, proof8_T1);
    rct::key xsq;
    sc_mul(xsq.bytes, pd.x.bytes, pd.x.bytes);
    sc_mul(tmp.bytes, xsq.bytes, weight_y.bytes);
    multiexp_data.emplace_back(tmp, proof8_T2);

    multiexp_data.emplace_back(weight_z, proof8_A);
    sc_mul(tmp.bytes, pd.x.bytes, weight_z.bytes);
    multiexp_data.emplace_back(tmp, proof8_S);

    // Compute the number of rounds for the inner product
    const size_t rounds = pd.logM+logN;
    LOG_ERROR_AND_RETURN_UNLESS(rounds > 0, false, "Zero rounds");

    // Compute the curvepoints from G[i] and H[i]
    rct::scalar yinvpow = rct::sone;
    rct::scalar ypow = rct::sone;

    const rct::scalar *winv = &inverses[pd.inv_offset];
    const rct::scalar yinv = inverses[pd.inv_offset + rounds];

    // precalc
    w_cache.resize(1<<rounds);
    w_cache[0] = winv[0];
    w_cache[1] = pd.w[0];
    for (size_t j = 1; j < rounds; ++j)
    {
      const size_t slots = 1<<(j+1);
      for (size_t s = slots; s-- > 0; --s)
      {
        sc_mul(w_cache[s].bytes, w_cache[s/2].bytes, pd.w[j].bytes);
        sc_mul(w_cache[s-1].bytes, w_cache[s/2].bytes, winv[j].bytes);
      }
    }

    for (size_t i = 0; i < MN; ++i)
    {
      rct::scalar g_scalar = proof.a;
      rct::scalar h_scalar;
      if (i == 0)
        h_scalar = proof.b;
      else
        sc_mul(h_scalar.bytes, proof.b.bytes, yinvpow.bytes);

      // Convert the index to binary IN REVERSE and construct the scalar exponent
      sc_mul(g_scalar.bytes, g_scalar.bytes, w_cache[i].bytes);
      sc_mul(h_scalar.bytes, h_scalar.bytes, w_cache[(~i) & (MN-1)].bytes);

      sc_add(g_scalar.bytes, g_scalar.bytes, pd.z.bytes);
      LOG_ERROR_AND_RETURN_UNLESS(2+i/N < zpow.size(), false, "invalid zpow index");
      LOG_ERROR_AND_RETURN_UNLESS(i%N < twoN.size(), false, "invalid twoN index");
      sc_mul(tmp.bytes, zpow[2+i/N].bytes, twoN[i%N].bytes);
      if (i == 0)
      {
        sc_add(tmp.bytes, tmp.bytes, pd.z.bytes);
        sc_sub(h_scalar.bytes, h_scalar.bytes, tmp.bytes);
      }
      else
      {
        sc_muladd(tmp.bytes, pd.z.bytes, ypow.bytes, tmp.bytes);
        sc_mulsub(h_scalar.bytes, tmp.bytes, yinvpow.bytes, h_scalar.bytes);
      }

      sc_mulsub(m_z4[i].bytes, g_scalar.bytes, weight_z.bytes, m_z4[i].bytes);
      sc_mulsub(m_z5[i].bytes, h_scalar.bytes, weight_z.bytes, m_z5[i].bytes);

      if (i == 0)
      {
        yinvpow = yinv;
        ypow = pd.y;
      }
      else if (i != MN-1)
      {
        sc_mul(yinvpow.bytes, yinvpow.bytes, yinv.bytes);
        sc_mul(ypow.bytes, ypow.bytes, pd.y.bytes);
      }
    }

    sc_muladd(z1.bytes, proof.mu.bytes, weight_z.bytes, z1.bytes);
    for (size_t i = 0; i < rounds; ++i)
    {
      sc_mul(tmp.bytes, pd.w[i].bytes, pd.w[i].bytes);
      sc_mul(tmp.bytes, tmp.bytes, weight_z.bytes);
      multiexp_data.emplace_back(tmp, proof8_L[i]);
      sc_mul(tmp.bytes, winv[i].bytes, winv[i].bytes);
      sc_mul(tmp.bytes, tmp.bytes, weight_z.bytes);
      multiexp_data.emplace_back(tmp, proof8_R[i]);
    }
    sc_mulsub(tmp.bytes, proof.a.bytes, proof.b.bytes, proof.t.bytes);
    sc_mul(tmp.bytes, tmp.bytes, pd.x_ip.bytes);
    sc_muladd(z3.bytes, tmp.bytes, weight_z.bytes, z3.bytes);
  }

  // now check all proofs at once
  sc_sub(tmp.bytes, m_y0.bytes, z1.bytes);
  multiexp_data.emplace_back(tmp, rct::G);
  sc_sub(tmp.bytes, z3.bytes, y1.bytes);
  multiexp_data.emplace_back(tmp, rct::H);
  for (size_t i = 0; i < maxMN; ++i)
  {
    multiexp_data[i * 2] = {m_z4[i], Gi_p3[i]};
    multiexp_data[i * 2 + 1] = {m_z5[i], Hi_p3[i]};
  }
  if (!(multiexp(multiexp_data) == rct::identity))
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
