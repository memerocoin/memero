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

#include "math/crypto/controller/keyGen.hpp"
#include "math/crypto/controller/random.hpp"

#include "math/ringct/functional/rctTypes.hpp"
#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/pseudo_functional/bulletproofs.hpp"
#include "math/ringct/controller/bulletproofs_gen.hpp"

#include <tuple>

using namespace rct;
using namespace crypto;

bp_input_t random_bp_input() {
  return { randomAmount(), randomScalar() };
}

std::pair<rct_pointV, std::vector<bp_input_t>>
random_bp_inputs_for_size(const size_t i) {
  if (i < 1) return {};

  std::vector<bp_input_t> xs;
  std::generate_n
    (
     std::back_inserter(xs)
     , i
     , random_bp_input
     );

  rct_pointV commits;
  std::transform
    (
     xs.begin()
     , xs.end()
     , std::back_inserter(commits)
     , [](const auto& x) { return std::apply(commit, x); }
     );

  return {commits, xs};
}

  
TEST(quick_bulletproofs, pick_amount_size_1_to_16)
{
  const size_t i = rand_range(1, 16);
  const auto x = random_bp_inputs_for_size(i);
  const auto proof = bulletproof_MAKE(x.second);
  EXPECT_TRUE(bulletproof_VERIFY(x.first, proof));
}

// struct Bulletproof
// {
//   rct::rct_pointV commits;
//   rct::rct_point A, S;
//   rct::rct_point T1, T2;
//   rct::rct_scalar taux, mu;
//   LR_V LR;
//   rct::rct_scalar a, b, t;
// };

std::pair<rct_pointV, Bulletproof> randomProof() {
  const size_t i = rand_range(1, 16);
  const auto x = random_bp_inputs_for_size(i);
  const auto proof = bulletproof_MAKE(x.second);
  return {x.first, proof};
}

TEST(quick_bulletproofs, wrong_A)
{
  const auto input = randomProof();
  const auto proof = input.second;
  EXPECT_TRUE(bulletproof_VERIFY(input.first, proof));

  auto altered_proof = proof;
  altered_proof.A = randomPoint();
  EXPECT_FALSE(bulletproof_VERIFY(input.first,altered_proof));
}


TEST(quick_bulletproofs, wrong_S)
{
  const auto input = randomProof();
  const auto proof = input.second;
  EXPECT_TRUE(bulletproof_VERIFY(input.first, proof));

  auto altered_proof = proof;
  altered_proof.S = randomPoint();
  EXPECT_FALSE(bulletproof_VERIFY(input.first, altered_proof));
}


TEST(quick_bulletproofs, wrong_T1)
{
  const auto input = randomProof();
  const auto proof = input.second;
  EXPECT_TRUE(bulletproof_VERIFY(input.first, proof));

  auto altered_proof = proof;
  altered_proof.T1 = randomPoint();
  EXPECT_FALSE(bulletproof_VERIFY(input.first, altered_proof));
}

TEST(quick_bulletproofs, wrong_T2)
{
  const auto input = randomProof();
  const auto proof = input.second;
  EXPECT_TRUE(bulletproof_VERIFY(input.first, proof));

  auto altered_proof = proof;
  altered_proof.T2 = randomPoint();
  EXPECT_FALSE(bulletproof_VERIFY(input.first, altered_proof));
}

TEST(quick_bulletproofs, wrong_taux)
{
  const auto input = randomProof();
  const auto proof = input.second;
  EXPECT_TRUE(bulletproof_VERIFY(input.first, proof));

  auto altered_proof = proof;
  altered_proof.taux = randomScalar();
  EXPECT_FALSE(bulletproof_VERIFY(input.first, altered_proof));
}


TEST(quick_bulletproofs, wrong_mu)
{
  const auto input = randomProof();
  const auto proof = input.second;
  EXPECT_TRUE(bulletproof_VERIFY(input.first, proof));

  auto altered_proof = proof;
  altered_proof.mu = randomScalar();
  EXPECT_FALSE(bulletproof_VERIFY(input.first, altered_proof));
}

TEST(quick_bulletproofs, wrong_a)
{
  const auto input = randomProof();
  const auto proof = input.second;
  EXPECT_TRUE(bulletproof_VERIFY(input.first, proof));

  auto altered_proof = proof;
  altered_proof.a = randomScalar();
  EXPECT_FALSE(bulletproof_VERIFY(input.first, altered_proof));
}

TEST(quick_bulletproofs, wrong_b)
{
  const auto input = randomProof();
  const auto proof = input.second;
  EXPECT_TRUE(bulletproof_VERIFY(input.first, proof));

  auto altered_proof = proof;
  altered_proof.b = randomScalar();
  EXPECT_FALSE(bulletproof_VERIFY(input.first, altered_proof));
}

TEST(quick_bulletproofs, wrong_t)
{
  const auto input = randomProof();
  const auto proof = input.second;
  EXPECT_TRUE(bulletproof_VERIFY(input.first, proof));

  auto altered_proof = proof;
  altered_proof.t = randomScalar();
  EXPECT_FALSE(bulletproof_VERIFY(input.first, altered_proof));
}

TEST(quick_bulletproofs, wrong_LR_first)
{
  const auto input = randomProof();
  const auto proof = input.second;
  EXPECT_TRUE(bulletproof_VERIFY(input.first, proof));

  auto altered_proof = proof;

  const auto index_to_change = rand_idx(proof.LR.size());
  auto lr = proof.LR[index_to_change];
  lr.first = randomPoint();

  altered_proof.LR[index_to_change] = lr;
  EXPECT_FALSE(bulletproof_VERIFY(input.first, altered_proof));
}


TEST(quick_bulletproofs, wrong_LR_second)
{
  const auto input = randomProof();
  const auto proof = input.second;
  EXPECT_TRUE(bulletproof_VERIFY(input.first, proof));

  auto altered_proof = proof;

  const auto index_to_change = rand_idx(proof.LR.size());
  auto lr = proof.LR[index_to_change];
  lr.second = randomPoint();

  altered_proof.LR[index_to_change] = lr;
  EXPECT_FALSE(bulletproof_VERIFY(input.first, altered_proof));
}
