// Copyright (c) 2018, The Monero Project
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

#include "gtest/gtest.h"

#include "math/crypto/functional/key.hpp"
#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/multiexp.hpp"

#define TESTSCALAR []{ static const rct::rct_scalar TESTSCALAR = rct::skGen(); return TESTSCALAR; }()
#define TESTPOW2SCALAR []{ static const rct::rct_scalar TESTPOW2SCALAR = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}; return TESTPOW2SCALAR; }()
#define TESTSMALLSCALAR []{ static const rct::rct_scalar TESTSMALLSCALAR = {{5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}; return TESTSMALLSCALAR; }()
#define TESTPOINT []{ \
    static const rct::rct_point TESTPOINT = rct::multG(rct::skGen()); \
 return TESTPOINT;                                                   \
}()

static rct::rct_point basic(const std::vector<rct::MultiexpData> &data)
{
  rct::rct_point res = rct::identity;
  for (const auto &d: data)
  {
    rct::rct_point p3 = rct::multP(d.point, d.scalar);
    res = res + p3;
  }
  return res;
}

static rct::rct_point get_p(const rct::rct_point &point)
{
  EXPECT_TRUE(crypto::is_safe_point(point));
  return point;
}

// TEST(multiexp, pippenger_empty)
// {
//   std::vector<rct::MultiexpData> data;
//   data.push_back({rct::s_zero, rct::identity});
//   ASSERT_TRUE(basic(data) == pippenger(data));
// }

TEST(multiexp, pippenger_zero_and_non_zero)
{
  std::vector<rct::MultiexpData> data;
  data.push_back({rct::s_zero, get_p(TESTPOINT)});
  data.push_back({TESTSCALAR, get_p(TESTPOINT)});
  ASSERT_TRUE(basic(data) == pippenger(data));
}

TEST(multiexp, pippenger_pow2_scalar)
{
  std::vector<rct::MultiexpData> data;
  data.push_back({TESTPOW2SCALAR, get_p(TESTPOINT)});
  data.push_back({TESTSMALLSCALAR, get_p(TESTPOINT)});
  ASSERT_TRUE(basic(data) == pippenger(data));
}

TEST(multiexp, pippenger_only_zeroes)
{
  std::vector<rct::MultiexpData> data;
  for (int n = 0; n < 16; ++n)
    data.push_back({rct::s_zero, get_p(TESTPOINT)});
  ASSERT_TRUE(basic(data) == pippenger(data));
}

// TEST(multiexp, pippenger_only_identities)
// {
//   std::vector<rct::MultiexpData> data;
//   for (int n = 0; n < 16; ++n)
//     data.push_back({TESTSCALAR, get_p(rct::identity)});
//   ASSERT_TRUE(basic(data) == pippenger(data));
// }

TEST(multiexp, pippenger_random)
{
  std::vector<rct::MultiexpData> data;
  for (int n = 0; n < 32; ++n)
  {
    data.push_back({rct::skGen(), get_p(rct::multG(rct::skGen()))});
    ASSERT_TRUE(basic(data) == pippenger(data));
  }
}

TEST(multiexp, pippenger_cached)
{
  static constexpr size_t N = 256;
  std::vector<rct::MultiexpData> P(N);
  for (size_t n = 0; n < N; ++n)
  {
    P[n].scalar = rct::s_zero;
    P[n].point = rct::multG(rct::skGen());
  }
  for (size_t n = 0; n < N/16; ++n)
  {
    std::vector<rct::MultiexpData> data;
    size_t sz = 1 + crypto::rand<size_t>() % (N-1);
    for (size_t s = 0; s < sz; ++s)
    {
      data.push_back({rct::skGen(), P[s].point});
    }
    ASSERT_TRUE(basic(data) == pippenger(data));
  }
}

TEST(multiexp, scalarmult_triple)
{
  std::vector<rct::MultiexpData> data;
  rct::rct_point res;

  static const rct::rct_scalar scalars[] = {
    rct::s_zero,
    rct::s_one,
    rct::L,
    rct::s_eight,
    rct::s_inv_eight,
  };
  static const rct::rct_point points[] = {
    rct::identity,
    rct::H,
    rct::G,
  };

  data.resize(3);
  for (const rct::rct_scalar &x: scalars)
  {
    data[0].scalar = x;
    for (const rct::rct_scalar &y: scalars)
    {
      data[1].scalar = y;
      for (const rct::rct_scalar &z: scalars)
      {
        data[2].scalar = z;
        for (size_t i = 0; i < sizeof(points) / sizeof(points[0]); ++i)
        {
          data[1].point = points[i];
          for (size_t j = 0; j < sizeof(points) / sizeof(points[0]); ++j)
          {
            data[0].point = rct::G;
            data[2].point = points[j];

            res = rct::multG(data[0].scalar) + rct::multP(points[i], data[1].scalar)
              + rct::multP(points[j], data[2].scalar);
            ASSERT_TRUE(basic(data) == res);

            for (size_t k = 0; k < sizeof(points) / sizeof(points[0]); ++k)
            {
              data[0].point = points[k];
              res = rct::multP(points[k], data[0].scalar)
                + rct::multP(points[i], data[1].scalar)
                + rct::multP(points[j], data[2].scalar);

              ASSERT_TRUE(basic(data) == res);
            }
          }
        }
      }
    }
  }
}
