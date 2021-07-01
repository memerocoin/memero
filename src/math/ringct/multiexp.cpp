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

extern "C"
{
#include "math/crypto/crypto-ops.h"
}

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "multiexp"

#define MULTIEXP_PERF(x)

// Pippenger:
// 	1	2	3	4	5	6	7	8	9	bestN
// 2	555	598	621	804	1038	1733	2486	5020	8304	1
// 4	783	747	800	1006	1428	2132	3285	5185	9806	2
// 8	1174	1071	1095	1286	1640	2398	3869	6378	12080	2
// 16	2279	1874	1745	1739	2144	2831	4209	6964	12007	4
// 32	3910	3706	2588	2477	2782	3467	4856	7489	12618	4
// 64	7184	5429	4710	4368	4010	4672	6027	8559	13684	5
// 128	14097	10574	8452	7297	6841	6718	8615	10580	15641	6
// 256	27715	20800	16000	13550	11875	11400	11505	14090	18460	6
// 512	55100	41250	31740	26570	22030	19830	20760	21380	25215	6
// 1024	111520	79000	61080	49720	43080	38320	37600	35040	36750	8
// 2048	219480	162680	122120	102080	83760	70360	66600	63920	66160	8
// 4096	453320	323080	247240	210200	180040	150240	132440	114920	110560	9

namespace rct
{

static inline bool operator<(const rct::key &k0, const rct::key&k1)
{
  for (int n = 31; n >= 0; --n)
  {
    if (k0.bytes[n] < k1.bytes[n])
      return true;
    if (k0.bytes[n] > k1.bytes[n])
      return false;
  }
  return false;
}

static inline rct::key div2(const rct::key &k)
{
  rct::key res;
  int carry = 0;
  for (int n = 31; n >= 0; --n)
  {
    int new_carry = (k.bytes[n] & 1) << 7;
    res.bytes[n] = k.bytes[n] / 2 + carry;
    carry = new_carry;
  }
  return res;
}

static inline rct::key pow2(size_t n)
{
  CHECK_AND_ASSERT_THROW_MES(n < 256, "Invalid pow2 argument");
  rct::key res = rct::zero();
  res[n >> 3] |= 1<<(n&7);
  return res;
}

static inline int test(const rct::key &k, size_t n)
{
  if (n >= 256) return 0;
  return k[n >> 3] & (1 << (n & 7));
}

static inline void add(ge_p3 &p3, const ge_cached &other)
{
  ge_p1p1 p1;
  ge_add(&p1, &p3, &other);
  ge_p1p1_to_p3(&p3, &p1);
}

static inline void add(ge_p3 &p3, const ge_p3 &other)
{
  ge_cached cached;
  ge_p3_to_cached(&cached, &other);
  add(p3, cached);
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

typedef std::vector<ge_cached> pippenger_cache;

pippenger_cache pippenger_init_cache(const std::vector<MultiexpData> data)
{
  pippenger_cache cache(data.size());

  std::transform(data.begin(), data.end(), cache.begin(),
                 [](const MultiexpData x) -> ge_cached {
                   return ge_p3_to_cached_by_value(x.point);
                 }
                 );

  return cache;
}

rct::key pippenger(const std::vector<MultiexpData> data)
{
  const size_t c = get_pippenger_c(data.size());
  const size_t bucket_size = 1 << c;

  ge_p3 result = ge_p3_identity;
  bool result_init = false;
  std::vector<ge_p3> buckets(bucket_size);
  std::vector<bool> buckets_init(bucket_size);

  const pippenger_cache local_cache = std::move(pippenger_init_cache(data));

  rct::key maxscalar = rct::zero();
  for (size_t i = 0; i < data.size(); ++i)
  {
    if (maxscalar < data[i].scalar)
      maxscalar = data[i].scalar;
  }
  size_t groups = 0;
  while (groups < 256 && !(maxscalar < pow2(groups)))
    ++groups;
  groups = (groups + c - 1) / c;

  for (size_t k = groups; k-- > 0; )
  {
    if (result_init)
    {
      ge_p2 p2;
      ge_p3_to_p2(&p2, &result);
      for (size_t i = 0; i < c; ++i)
      {
        ge_p1p1 p1;
        ge_p2_dbl(&p1, &p2);
        if (i == c - 1)
          ge_p1p1_to_p3(&result, &p1);
        else
          ge_p1p1_to_p2(&p2, &p1);
      }
    }

    std::fill(buckets_init.begin(), buckets_init.end(), false);

    // partition scalars into buckets
    for (size_t i = 0; i < data.size(); ++i)
    {
      unsigned int bucket = 0;
      for (size_t j = 0; j < c; ++j)
        if (test(data[i].scalar, k*c+j))
          bucket |= 1<<j;
      if (bucket == 0)
        continue;
      CHECK_AND_ASSERT_THROW_MES(bucket < (1u<<c), "bucket overflow");
      if (buckets_init[bucket])
      {
        add(buckets[bucket], local_cache[i]);
      }
      else
      {
        buckets[bucket] = data[i].point;
        buckets_init[bucket] = true;
      }
    }

    // sum the buckets
    ge_p3 pail;
    bool pail_init = false;
    for (size_t i = (1<<c)-1; i > 0; --i)
    {
      if (buckets_init[i])
      {
        if (pail_init)
          add(pail, buckets[i]);
        else
        {
          pail = buckets[i];
          pail_init = true;
        }
      }
      if (pail_init)
      {
        if (result_init)
          add(result, pail);
        else
        {
          result = pail;
          result_init = true;
        }
      }
    }
  }

  rct::key res;
  ge_p3_tobytes(res.bytes, &result);
  return res;
}

}
