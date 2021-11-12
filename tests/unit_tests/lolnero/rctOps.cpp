/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include <gtest/gtest.h>

#include "math/ringct/functional/rctOps.hpp"
#include "math/crypto/functional/group.hpp"
#include "math/crypto/controller/keyGen.hpp"

using namespace crypto;
using namespace rct;

TEST(G_1,  g_1)
{
  EXPECT_EQ(G_(s_1), multBase(s_1));
}

TEST(G_8, g_8)
{
  EXPECT_EQ(G_(s_8), multBase(s_8));
}

TEST(H_1,  H_1)
{
  EXPECT_EQ(H_(s_1), H ^ s_1);
}

TEST(H_8, h_8)
{
  EXPECT_EQ(H_(s_8), H ^ s_8);
}

TEST(G_random, g_random)
{
  // for (size_t i = 0; i < 100; i++) {
    const auto a = scalarGen();
    EXPECT_EQ(G_(a), G ^ a);
  // }
}

TEST(H_random, h_random)
{
  // for (size_t i = 0; i < 100; i++) {
    const auto a = scalarGen();
    EXPECT_EQ(H_(a), H ^ a);
  // }
}
