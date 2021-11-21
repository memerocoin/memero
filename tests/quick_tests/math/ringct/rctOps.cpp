/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include <gtest/gtest.h>

#include "math/ringct/functional/rctOps.hpp"

#include "math/crypto/functional/group.hpp"
#include "math/crypto/controller/keyGen.hpp"

using namespace crypto;
using namespace rct;


TEST(base_scalar_mult,  1)
{
  EXPECT_EQ(G_(s_1), crypto::generator);
}

TEST(H_scalar_mult,  H_1)
{
  EXPECT_EQ(H_(s_1), H);
}

TEST(rctOps_G_random, g_random)
{
  const auto a = randomScalar();
  EXPECT_EQ(G_(a), multBase(a));
}

TEST(rctOps_H_random, h_random)
{
    const auto a = randomScalar();
    EXPECT_EQ(H_(a), H ^ a);
}

TEST(s_minus_one, is_well_defined)
{
  EXPECT_EQ(s_minus_one, order_minus_1);
}


// test suites

class scalar_mult_G : public testing::TestWithParam<uint64_t> {};

TEST_P(scalar_mult_G, by) {
  const auto a = int_to_scalar(GetParam());

  EXPECT_EQ(G_(a), multBase(a));
}

INSTANTIATE_TEST_SUITE_P
(
 SUITE_rctOps
 , scalar_mult_G
 , testing::Range<uint64_t>(1, 9)
 );

class scalar_mult_H : public testing::TestWithParam<uint64_t> {};

TEST_P(scalar_mult_H, by) {
  const auto a = int_to_scalar(GetParam());

  EXPECT_EQ(H_(a), H ^ a);
}

INSTANTIATE_TEST_SUITE_P
(
 SUITE_rctOps
 , scalar_mult_H
 , testing::Range<uint64_t>(1, 9)
 );

