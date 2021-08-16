// Copyright (c) 2017, The Monero Project
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
// Adapted from Python code by Sarang Noether

#include "rctOps.hpp"
#include "multiexp.hpp"

#include <unordered_map>

extern "C"
{
#include "math/crypto/crypto-ops.h"
}

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "multiexp"


namespace rct
{

rct::key dummy(const std::span<rct::MultiexpData> data)
{
  return std::transform_reduce
    (
      data.begin()
      , data.end()
      , rct::identity
      , std::plus<key>()
      , [](const auto& x) {
        return rct::multP(x.point, x.scalar);
      }
      );
}


static inline rct::scalar pow2(size_t n)
{
  LOG_ERROR_AND_THROW_UNLESS(n < 256, "Invalid pow2 argument");
  rct::scalar res = {};
  res.data[n >> 3] |= 1<<(n&7);
  return res;
}

static inline int test(const rct::scalar &k, size_t n)
{
  if (n >= 256) return 0;
  return k.data[n >> 3] & (1 << (n & 7));
}

size_t get_pippenger_c(size_t N)
{
  if (N <= 13) return 2;
  if (N <= 29) return 3;
  if (N <= 83) return 4;
  if (N <= 185) return 5;
  if (N <= 465) return 6;
  if (N <= 1180) return 7;
  if (N <= 2295) return 8;
  return 9;
}

typedef std::vector<key> pippenger_cache;

pippenger_cache pippenger_init_cache(const std::span<MultiexpData> data)
{
  pippenger_cache cache(data.size());

  std::transform(data.begin(), data.end(), cache.begin(),
                 [](const MultiexpData x) -> key {
                   return x.point;
                 }
                 );

  return cache;
}

bool operator<(const rct::scalar &k0, const rct::scalar &k1)
{
  for (int n = 31; n >= 0; --n)
    {
      if (k0.data[n] < k1.data[n])
        return true;
      if (k0.data[n] > k1.data[n])
        return false;
    }
  return false;
}

rct::key pippenger(const std::span<MultiexpData> data)
{
  const pippenger_cache local_cache = pippenger_init_cache(data);
  const size_t c = get_pippenger_c(data.size());

  key result = identity;
  bool result_init = false;

  const rct::scalar maxscalar = data.empty() ? rct::s_zero :
    (
     *std::max_element(data.begin(), data.end(),
                       [](const auto x, const auto y) -> bool { return x.scalar < y.scalar; })
     ).scalar;

  size_t groups = 0;
  while (groups < 256 && !(maxscalar < pow2(groups)))
    ++groups;
  groups = (groups + c - 1) / c;

  for (size_t k = groups; k-- > 0; )
  {
    if (result_init)
    {
      key p2 = result;
      for (size_t i = 0; i < c; ++i)
      {
        key p1 = p2 * 2;
        if (i == c - 1)
          result = p1;
        else
          p2 = p1;
      }
    }

    std::unordered_map<size_t, key> buckets;

    // partition scalars into buckets
    for (size_t i = 0; i < data.size(); ++i)
    {
      size_t bucket = 0;
      for (size_t j = 0; j < c; ++j)
        if (test(data[i].scalar, k*c+j))
          bucket |= 1<<j;
      if (bucket == 0)
        continue;
      LOG_ERROR_AND_THROW_UNLESS(bucket < (1u<<c), "bucket overflow");
      if (buckets.contains(bucket))
      {
        buckets[bucket] = buckets[bucket] + local_cache[i];
      }
      else
      {
        buckets.emplace(bucket, data[i].point);
      }
    }

    // sum the buckets
    key pail;
    bool pail_init = false;
    for (size_t i = (1<<c)-1; i > 0; --i)
    {
      if (buckets.contains(i))
      {
        if (pail_init)
          pail = pail + buckets[i];
        else
        {
          pail = buckets[i];
          pail_init = true;
        }
      }
      if (pail_init)
      {
        if (result_init)
          result = result + pail;
        else
        {
          result = pail;
          result_init = true;
        }
      }
    }
  }

  return result;
}

}
