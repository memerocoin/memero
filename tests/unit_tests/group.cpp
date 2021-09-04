/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include <gtest/gtest.h>

#include "math/crypto/functional/group.hpp"
#include "math/crypto/controller/keyGen.hpp"

using namespace crypto;

TEST(EC_Group, g_is_a_group_element)
{
  EXPECT_TRUE(is_not_identity_but_valid(generator));
}

TEST(EC_Group, i_is_usually_not_accepted)
{
  EXPECT_FALSE(is_not_identity_but_valid(identity));
}

TEST(EC_Group, i_is_a_valid_group_element)
{
  EXPECT_TRUE(is_valid_group_element(identity));
}

TEST(EC_Group, g_mult_l_is_identity)
{
  EXPECT_EQ((generator ^ order_minus_1) + generator, identity);
}

TEST(EC_Group, anything_mult_l_is_identity)
{
  const auto a = randomPoint();
  EXPECT_EQ((a ^ order_minus_1) + a, identity);
}

TEST(EC_Group, is_a_semigroup_for_Associativity)
{
  const auto a = randomPoint();
  const auto b = randomPoint();
  const auto c = randomPoint();

  EXPECT_EQ((a + b) + c, a + (b + c));
}

TEST(EC_Group, is_a_monoid_with_an_embeded_Identity)
{
  const auto a = randomPoint();

  EXPECT_EQ(identity + a, a);
  EXPECT_EQ(a + identity, a);
}

TEST(EC_Group, is_a_group_for_Invertibility)
{
  const auto a = randomPoint();
  const auto inv_a = identity - a;

  EXPECT_EQ(a + inv_a, identity);
  EXPECT_EQ(inv_a + a, identity);
}

