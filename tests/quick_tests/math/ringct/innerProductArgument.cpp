/*

Copyright 2021 fuwa

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

#include <gtest/gtest.h>

#include "math/crypto/controller/keyGen.hpp"
#include "math/crypto/controller/random.hpp"

#include "math/ringct/functional/rctTypes.hpp"
#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/functional/vectorOps.hpp"
#include "math/ringct/functional/innerProductArgument.hpp"
#include "math/ringct/functional/bulletproofs.hpp"

#include "tools/epee/include/logging.hpp"

#include <tuple>

using namespace rct;

std::tuple<scalarV, scalarV>
random_vector_pair(const size_t i) {
  if (i < 1) return {};
  const auto u = crypto::randomScalars(i);
  const auto v = crypto::randomScalars(i);

  return {u, v};
}

std::tuple
<
  InnerProductArgument
  , scalarV
  , scalarV
  >
randomIPA() {
  const size_t i_exp = crypto::rand_range(1, 8);
  const size_t i = 1 << i_exp;

  const auto G = get_bp_generator_G_V(i);
  const auto H = get_bp_generator_H_V(i);
  const auto u = crypto::randomPoint();

  const auto [a, b] = random_vector_pair(i);

  const auto ipa = init_inner_product_argument
    (
     G
     , H
     , a
     , b
     , u
     );

  return {ipa, a, b};
}

std::tuple
<
  RecursiveInnerProductArgument
  , scalarV
  , scalarV
  , crypto::ec_scalar
  >
random_recursive_IPA() {
  // const size_t i_exp = crypto::rand_range(1, 8);
  // const size_t i = 1 << i_exp;
  const size_t i = 2;

  const auto G = get_bp_generator_G_V(i);
  const auto H = get_bp_generator_H_V(i);
  const auto u = crypto::randomPoint();
  const auto challenge = crypto::randomScalar();

  const auto [a, b] = random_vector_pair(i);

  std::optional<RecursiveInnerProductArgument> maybe_ipa = {};

  while (!maybe_ipa) {
    maybe_ipa = make_recursive_inner_product_argument
      (
       G
       , H
       , a
       , b
       , u
       , challenge
       );
  }

  const auto ipa = *maybe_ipa;

  return {ipa, a, b, challenge};
}

TEST(quick_ipa, simple)
{
  const auto [ipa, a, b] = randomIPA();
  const auto challenge = crypto::randomScalar();

  const auto [a_half, b_half] =
    finish_inner_product_argument(a, b, challenge);

  EXPECT_TRUE(verify_inner_product_argument
              (ipa, challenge, a_half, b_half));
}


TEST(quick_homomorphic_hash_full, simple)
{
  const size_t i_exp = crypto::rand_range(1, 8);
  const size_t i = 1 << i_exp;

  const auto G = get_bp_generator_G_V(i);
  const auto H = get_bp_generator_H_V(i);

  const auto [a, b] = random_vector_pair(i);

  const auto u = crypto::randomPoint();

  const auto [G_L, G_R] = split_vector(G);
  const auto [H_L, H_R] = split_vector(H);
  const auto [a_L, a_R] = split_vector(a);
  const auto [b_L, b_R] = split_vector(b);

  const auto c = inner_product(a, b);

  EXPECT_EQ
    (homomorphic_hash_full(G, H, a_L, a_R, b_L, b_R, u, c)
     , homomorphic_hash(G_L, H_L, a_L, b_L, u, c)
     + homomorphic_hash(G_R, H_R, a_R, b_R, u, crypto::s_0)
     );
}


TEST(quick_ipa_non_interactive, simple)
{
  const auto [ipa, a, b, challenge] = random_recursive_IPA();

  // bool verify_recursive_inner_product_argument
  // (
  //  const RecursiveInnerProductArgument ipa
  //  , const crypto::ec_scalar challenge
  //  );

  EXPECT_TRUE
    (verify_recursive_inner_product_argument(ipa, challenge));
}
