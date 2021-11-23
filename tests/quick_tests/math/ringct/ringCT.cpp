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

#include "math/ringct/functional/rctTypes.hpp"
#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/pseudo_functional/ringCT.hpp"
#include "math/ringct/controller/ringCT_Gen.hpp"

#include "math/crypto/functional/key.hpp"
#include "math/crypto/controller/keyGen.hpp"
#include "math/crypto/controller/random.hpp"

#include "tools/epee/include/logging.hpp"

#include "config/lol.hpp"

using namespace rct;
using namespace crypto;

// struct rctInputData
// {
//   const amount_t amount;
//   const rct_scalar signer_sk;
//   const rct_scalar signer_blinding_factor;
//   const size_t index_in_decoys;
//   const output_public_dataV decoys;
// };

constexpr uint64_t max_input_size = 32;
constexpr uint64_t max_output_size = 16;
constexpr uint64_t input_base = 1ull << 40;

rctInputData randomRctInputData() {
  const amount_t amount = rand_range<uint64_t>(0, input_base) + input_base;

  const rct_scalar signer_sk = randomScalar();
  const rct_scalar signer_blinding_factor = randomScalar();
  const size_t index_in_decoys = rand_idx(config::lol::ring_size);


  output_public_dataV decoys;
  std::generate_n
    (
     std::back_inserter(decoys)
     , config::lol::ring_size
     , []() -> output_public_data {
       return {
         randomPoint()
         , randomPoint()
       };
     }
     );

  const rct_point real_input_commit = commit(amount, signer_blinding_factor);
  decoys[index_in_decoys] = {to_pk(s2sk(signer_sk)), real_input_commit};

  return {
    amount
    , signer_sk
    , signer_blinding_factor
    , index_in_decoys
    , decoys
  };
}

// struct rctOutputData
// {
//   const amount_t amount;
//   const rct_scalar ecdh_shared_secret_hashed_by_index;
// };

rctOutputData randomRctOutputData() {
  return { rand_range<uint64_t>(1, 1ull << 30), randomScalar() };
}

// rctData generate_ringct
// (
//  const crypto::hash message
//  , const std::vector<rctInputData> inputs
//  , const std::vector<rctOutputData> outputs
//  , const amount_t fee
//  );

struct rctDataInput {
   crypto::hash message;
   std::vector<rctInputData> inputs;
   std::vector<rctOutputData> outputs;
   amount_t fee;
};

rctDataInput randomRctDataInput() {
  const crypto::hash message = d2h(randomCryptoData());

  std::vector<rctInputData> inputs;
  std::generate_n
    (
     std::back_inserter(inputs)
     , rand_range<size_t>(1, max_input_size)
     , randomRctInputData
     );

  std::vector<rctOutputData> outputs;
  std::generate_n
    (
     std::back_inserter(outputs)
     , rand_range<size_t>(1, max_output_size)
     , randomRctOutputData
     );

  const amount_t sum_inputs = std::transform_reduce
    (
     inputs.begin()
     , inputs.end()
     , 0ull
     , std::plus()
     , [](const auto& x) -> amount_t {
       return x.amount;
       }
     );

  const amount_t sum_outputs = std::transform_reduce
    (
     outputs.begin()
     , outputs.end()
     , 0ull
     , std::plus()
     , [](const auto& x) -> amount_t {
       return x.amount;
     }
     );

  assert(sum_inputs >= sum_outputs);
  const amount_t fee = sum_inputs - sum_outputs;

  return {
    message
    , inputs
    , outputs
    , fee
  };

}


TEST(quick_ringct, random_input)
{
  const auto i = randomRctDataInput();

  const auto x = generate_ringct
    (
     i.message
     , i.inputs
     , i.outputs
     , i.fee
     );

  const auto maybe_size_checked_rct_data = maybeSizeCheckedRctData(x);
  EXPECT_TRUE(maybe_size_checked_rct_data);
  const auto checked = *maybe_size_checked_rct_data;


  EXPECT_TRUE(verify_range_proof(checked));
  EXPECT_TRUE(verify_tx_balance(x));
  EXPECT_TRUE(verify_clsag_signatures(x));
  EXPECT_TRUE(verify_ringct(x));
}

// uint8_t type = RCTTypeNull;
// crypto::hash message;
// output_public_dataM decoys;
// std::vector<ecdh_encrypted_data_t> ecdh_encrypted_data;
// std::vector<output_commit> output_commits;
// amount_t fee;

amount_t randomAmountBut(const amount_t x) {
  const amount_t r = randomAmount();
  return
    r == x
    ? randomAmountBut(x)
    : r
    ;
}


TEST(quick_ringct, wrong_balance)
{
  const auto i = randomRctDataInput();

  const auto x = generate_ringct
    (
     i.message
     , i.inputs
     , i.outputs
     , i.fee
     );

  EXPECT_TRUE(verify_ringct(x));

  auto altered_data = x;
  altered_data.fee = randomAmountBut(x.fee);

  EXPECT_FALSE(verify_ringct(altered_data));
}


TEST(quick_ringct, wrong_message)
{
  const auto i = randomRctDataInput();

  const auto x = generate_ringct
    (
     i.message
     , i.inputs
     , i.outputs
     , i.fee
     );

  EXPECT_TRUE(verify_ringct(x));

  auto altered_data = x;
  altered_data.message = d2h(randomCryptoData());

  EXPECT_FALSE(verify_ringct(altered_data));
}


TEST(quick_ringct, wrong_type)
{
  const auto i = randomRctDataInput();

  const auto x = generate_ringct
    (
     i.message
     , i.inputs
     , i.outputs
     , i.fee
     );

  EXPECT_TRUE(verify_ringct(x));

  auto altered_data = x;
  altered_data.type = RCTTypeNull;

  EXPECT_FALSE(verify_ringct(altered_data));
}

TEST(quick_ringct, wrong_ecdh_encrypted_data)
{
  const auto i = randomRctDataInput();

  const auto x = generate_ringct
    (
     i.message
     , i.inputs
     , i.outputs
     , i.fee
     );

  EXPECT_TRUE(verify_ringct(x));

  auto altered_data = x;

  const auto index_to_change = rand_idx(x.ecdh_encrypted_data.size());
  const auto masked_amount = x.ecdh_encrypted_data[index_to_change].masked_amount;
  altered_data.ecdh_encrypted_data[index_to_change].masked_amount =
    randomAmountBut(masked_amount);

  EXPECT_FALSE(verify_ringct(altered_data));
}

TEST(quick_ringct, wrong_output_commit_size)
{
  const auto i = randomRctDataInput();

  const auto x = generate_ringct
    (
     i.message
     , i.inputs
     , i.outputs
     , i.fee
     );

  EXPECT_TRUE(verify_ringct(x));

  auto altered_data = x;

  auto commits = x.output_commits;
  commits.pop_back();
  altered_data.output_commits = commits;

  EXPECT_FALSE(verify_ringct(altered_data));
}
