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


#include "innerProductArgument_gen.hpp"

#include "math/ringct/functional/vectorOps.hpp"
#include "math/ringct/functional/rctOps.hpp"

#include "tools/epee/include/logging.hpp"

namespace rct
{
  InnerProductArgument init_inner_product_argument
  (
   const pointS G
   , const pointS H
   , const scalarS a
   , const scalarS b
   , const crypto::ec_point u
   )
  {
    const auto [a_L, a_R] = split_vector(a);
    const auto [b_L, b_R] = split_vector(b);

    const crypto::ec_scalar c_L = inner_product(a_L, b_R);
    const crypto::ec_scalar c_R = inner_product(a_R, b_L);

    const auto [G_L, G_R] = split_vector(G);
    const auto [H_L, H_R] = split_vector(H);

    const auto L = homomorphic_hash(G_R, H_L, a_L, b_R, u, c_L);
    const auto R = homomorphic_hash(G_L, H_R, a_R, b_L, u, c_R);

    const auto t = inner_product(a, b);
    const auto P = homomorphic_hash(G, H, a, b, u, t);
 
    return
      {
        P
        , span_to_vector(G)
        , span_to_vector(H)
        , L
        , R
        , u
      };
  }

  std::tuple
  <
    const scalarV
    , const scalarV
    >
  finish_inner_product_argument
  (
   const scalarS a
   , const scalarS b
   , const crypto::ec_scalar challenge
   )
  {
    const auto [a_L, a_R] = split_vector(a);
    const auto [b_L, b_R] = split_vector(b);

    const crypto::ec_scalar challenge_inv =
      crypto::multiplicative_inverse(challenge);

    const auto new_a = vector_add_V
      (
       vector_mult(a_L, challenge)
       , vector_mult(a_R, challenge_inv)
       );

    const auto new_b = vector_add_V
      (
       vector_mult(b_L, challenge_inv)
       , vector_mult(b_R, challenge)
       );

    return {new_a, new_b};
  }


  std::tuple
  <
    const pointV
    , const pointV
    >
  split_generators_with_challenge
  (
   const pointS G
   , const pointS H
   , const crypto::ec_scalar challenge
   )
  {
    const auto [G_L, G_R] = split_vector(G);
    const auto [H_L, H_R] = split_vector(H);

    const crypto::ec_scalar challenge_inv =
      crypto::multiplicative_inverse(challenge);

    const auto new_G = vector_add_V
      (
       scalar_multP_V(challenge_inv, G_L)
       , scalar_multP_V(challenge, G_R)
       );

    const auto new_H = vector_add_V
      (
       scalar_multP_V(challenge, H_L)
       , scalar_multP_V(challenge_inv, H_R)
       );

    return {new_G, new_H};
  }

  std::optional<RecursiveInnerProductArgument>
  make_recursive_inner_product_argument
  (
   const crypto::ec_point P
   , const pointS G_0
   , const pointS H_0
   , const pointS G
   , const pointS H
   , const scalarS a
   , const scalarS b
   , const crypto::ec_point u
   , const crypto::ec_scalar challenge
   , const LR_V LR
   )
  {
    if (G.empty()) {
      LOG_FATAL("Generator shouldn't be emtpy");
      return {};
    }

    if (G.size() == 1) {
      return RecursiveInnerProductArgument
        {
          P
          , span_to_vector(G_0)
          , span_to_vector(H_0)
          , LR
          , a.front()
          , b.front()
          , u
        };
    }

    const auto ipa = init_inner_product_argument
      (
       G
       , H
       , a
       , b
       , u
       );

    const auto maybe_new_challenge = maybe_hash_V_to_non_zero_scalar
      (crypto::dataV{challenge, to_inv8(ipa.L), to_inv8(ipa.R)});

    if (!maybe_new_challenge) {
      return {};
    }

    const auto new_challenge = *maybe_new_challenge;

    const auto [a_half, b_half] = finish_inner_product_argument
      (
       a, b, new_challenge
       );

    LR_V new_LR = LR;
    new_LR.emplace_back(ipa.L, ipa.R);

    const auto [G_half, H_half] =
      split_generators_with_challenge
      (
       G
       , H
       , new_challenge
       );

    return make_recursive_inner_product_argument
      (
       P
       , G_0
       , H_0
       , G_half
       , H_half
       , a_half
       , b_half
       , u
       , new_challenge
       , new_LR
       );
  }

  std::optional<RecursiveInnerProductArgument>
  make_recursive_inner_product_argument
  (
   const pointS G
   , const pointS H
   , const scalarS a
   , const scalarS b
   , const crypto::ec_point u
   , const crypto::ec_scalar challenge
   )
  {

    const auto t = inner_product(a, b);
    const auto P = homomorphic_hash(G, H, a, b, u, t);

    return make_recursive_inner_product_argument
      (
       P
       , G
       , H
       , G
       , H
       , a
       , b
       , u
       , challenge
       , {}
       );
  }
}
