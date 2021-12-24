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

#include "math/crypto/functional/key.hpp"
#include "math/crypto/controller/keyGen.hpp"
#include "math/crypto/controller/random.hpp"

#include "math/ringct/functional/rctTypes.hpp"
#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/pseudo_functional/clsag.hpp"
#include "math/ringct/controller/clsagGen.hpp"

#include "config/lol.hpp"

using namespace rct;
using namespace crypto;


struct clsagInput
{
 crypto::hash message;
 rct_scalar signer_sk;
 rct_scalar signer_blinding_factor;
 size_t index_in_decoys;
 rct_scalar pseudo_input_blinding_factor;
 rct_point pseudo_input_commit;
 output_public_dataV decoys;
}; 

clsagInput randomClsagInput() {
  const crypto::hash message = d2h(randomCryptoData());
  const rct_scalar signer_sk = randomScalar();
  const rct_scalar signer_blinding_factor = randomScalar();
  const size_t index_in_decoys = rand_idx(config::lol::ring_size);
  const rct_scalar pseudo_input_blinding_factor = randomScalar();

  const amount_t some_amount = randomAmount();
  const rct_point pseudo_input_commit = commit(some_amount, pseudo_input_blinding_factor);
  const rct_point real_input_commit = commit(some_amount, signer_blinding_factor);

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

  decoys[index_in_decoys] = {to_pk(s2sk(signer_sk)), real_input_commit};

  return {
    message
    , signer_sk
    , signer_blinding_factor
    , index_in_decoys
    , pseudo_input_blinding_factor
    , pseudo_input_commit
    , decoys
  };
}

TEST(quick_clsag, random_input)
{
  const auto i = randomClsagInput();
  const auto sig = generate_clsag_signature
    (
     i.message
     , i.signer_sk
     , i.signer_blinding_factor
     , i.index_in_decoys
     , i.pseudo_input_blinding_factor
     , i.pseudo_input_commit
     , i.decoys
     );

  EXPECT_TRUE(verify_clsag_signature(i.message, sig, i.decoys, i.pseudo_input_commit));
}


TEST(quick_clsag, wrong_message)
{
  const auto i = randomClsagInput();
  const auto sig = generate_clsag_signature
    (
     i.message
     , i.signer_sk
     , i.signer_blinding_factor
     , i.index_in_decoys
     , i.pseudo_input_blinding_factor
     , i.pseudo_input_commit
     , i.decoys
     );

  EXPECT_TRUE(verify_clsag_signature(i.message, sig, i.decoys, i.pseudo_input_commit));

  const crypto::hash message = d2h(randomCryptoData());
  EXPECT_FALSE(verify_clsag_signature(message, sig, i.decoys, i.pseudo_input_commit));
}


TEST(quick_clsag, wrong_decoys_1)
{
  const auto i = randomClsagInput();
  const auto sig = generate_clsag_signature
    (
     i.message
     , i.signer_sk
     , i.signer_blinding_factor
     , i.index_in_decoys
     , i.pseudo_input_blinding_factor
     , i.pseudo_input_commit
     , i.decoys
     );

  EXPECT_TRUE(verify_clsag_signature(i.message, sig, i.decoys, i.pseudo_input_commit));

  auto decoys = i.decoys;
  const size_t index_in_decoys = rand_idx(config::lol::ring_size);
  const auto decoy = decoys[index_in_decoys];

  const output_public_data wrong_decoy_1 = {randomPoint(), decoy.commit};
  decoys[index_in_decoys] = wrong_decoy_1;

  EXPECT_FALSE(verify_clsag_signature(i.message, sig, decoys, i.pseudo_input_commit));
}

TEST(quick_clsag, wrong_decoys_2)
{
  const auto i = randomClsagInput();
  const auto sig = generate_clsag_signature
    (
     i.message
     , i.signer_sk
     , i.signer_blinding_factor
     , i.index_in_decoys
     , i.pseudo_input_blinding_factor
     , i.pseudo_input_commit
     , i.decoys
     );

  EXPECT_TRUE(verify_clsag_signature(i.message, sig, i.decoys, i.pseudo_input_commit));

  auto decoys = i.decoys;
  const size_t index_in_decoys = rand_idx(config::lol::ring_size);
  const auto decoy = decoys[index_in_decoys];

  const output_public_data wrong_decoy_2 = {decoy.output_public_key, randomPoint()};
  decoys[index_in_decoys] = wrong_decoy_2;

  EXPECT_FALSE(verify_clsag_signature(i.message, sig, decoys, i.pseudo_input_commit));
}


TEST(quick_clsag, wrong_pseudo_input_commit)
{
  const auto i = randomClsagInput();
  const auto sig = generate_clsag_signature
    (
     i.message
     , i.signer_sk
     , i.signer_blinding_factor
     , i.index_in_decoys
     , i.pseudo_input_blinding_factor
     , i.pseudo_input_commit
     , i.decoys
     );

  EXPECT_TRUE(verify_clsag_signature(i.message, sig, i.decoys, i.pseudo_input_commit));

  const auto pseudo_input_commit = randomPoint();

  EXPECT_FALSE(verify_clsag_signature(i.message, sig, i.decoys, pseudo_input_commit));
}


// struct clsag
// {
//   rct_scalarV s; // scalars
//   rct_scalar c1;
//   rct_point signer_key_image; // signing key image
//   rct_point blinding_factor_surplus_key_image; // commitment key image
// };

TEST(quick_clsag, wrong_sig_c1)
{
  const auto i = randomClsagInput();
  const auto sig = generate_clsag_signature
    (
     i.message
     , i.signer_sk
     , i.signer_blinding_factor
     , i.index_in_decoys
     , i.pseudo_input_blinding_factor
     , i.pseudo_input_commit
     , i.decoys
     );

  EXPECT_TRUE(verify_clsag_signature(i.message, sig, i.decoys, i.pseudo_input_commit));

  clsag sig1 = sig;

  sig1.c1 = randomScalar();

  EXPECT_FALSE(verify_clsag_signature(i.message, sig1, i.decoys, i.pseudo_input_commit));
}


TEST(quick_clsag, wrong_sig_signer_key_image)
{
  const auto i = randomClsagInput();
  const auto sig = generate_clsag_signature
    (
     i.message
     , i.signer_sk
     , i.signer_blinding_factor
     , i.index_in_decoys
     , i.pseudo_input_blinding_factor
     , i.pseudo_input_commit
     , i.decoys
     );

  EXPECT_TRUE(verify_clsag_signature(i.message, sig, i.decoys, i.pseudo_input_commit));

  clsag sig1 = sig;

  sig1.signer_key_image = randomPoint();

  EXPECT_FALSE(verify_clsag_signature(i.message, sig1, i.decoys, i.pseudo_input_commit));
}

TEST(quick_clsag, wrong_sig_blinding_factor_surplus_key_image)
{
  const auto i = randomClsagInput();
  const auto sig = generate_clsag_signature
    (
     i.message
     , i.signer_sk
     , i.signer_blinding_factor
     , i.index_in_decoys
     , i.pseudo_input_blinding_factor
     , i.pseudo_input_commit
     , i.decoys
     );

  EXPECT_TRUE(verify_clsag_signature(i.message, sig, i.decoys, i.pseudo_input_commit));

  clsag sig1 = sig;

  sig1.blinding_factor_surplus_key_image = randomPoint();

  EXPECT_FALSE(verify_clsag_signature(i.message, sig1, i.decoys, i.pseudo_input_commit));
}


TEST(quick_clsag, wrong_sig_s)
{
  const auto i = randomClsagInput();
  const auto sig = generate_clsag_signature
    (
     i.message
     , i.signer_sk
     , i.signer_blinding_factor
     , i.index_in_decoys
     , i.pseudo_input_blinding_factor
     , i.pseudo_input_commit
     , i.decoys
     );

  EXPECT_TRUE(verify_clsag_signature(i.message, sig, i.decoys, i.pseudo_input_commit));

  clsag sig1 = sig;

  const auto index_to_change = rand_idx(sig1.s.size());
  sig1.s[index_to_change] = randomScalar();

  EXPECT_FALSE(verify_clsag_signature(i.message, sig1, i.decoys, i.pseudo_input_commit));
}
