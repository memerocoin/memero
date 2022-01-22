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


#include "innerProductArgument.hpp"

#include "math/ringct/functional/vectorOps.hpp"
#include "math/ringct/functional/rctOps.hpp"

#include "tools/epee/include/logging.hpp"

namespace rct
{
  std::pair<crypto::ec_point, crypto::ec_point>
  init_inner_product_argument
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

    return {L, R};
  }

  std::tuple
  <
    const pointV
    , const pointV
    , const scalarV
    , const scalarV
    >
  reduce_inner_product_argument
  (
   const pointS G
   , const pointS H
   , const scalarS a
   , const scalarS b
   , const crypto::ec_scalar challenge
   )
  {
    const auto [a_L, a_R] = split_vector(a);
    const auto [b_L, b_R] = split_vector(b);

    const auto [G_L, G_R] = split_vector(G);
    const auto [H_L, H_R] = split_vector(H);

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

    return {new_G, new_H, new_a, new_b};
  }

  std::optional<
    std::tuple
    < LR_V
      , crypto::ec_scalar
      , crypto::ec_scalar
      >
    >
  make_recursive_inner_product_argument
  (
   const pointS _G
   , const pointS _H
   , const scalarS _a
   , const scalarS _b
   , const crypto::ec_point u
   , const crypto::ec_scalar challenge
   )
  {
    pointV G = span_to_vector(_G);
    pointV H = span_to_vector(_H);
    scalarV a = span_to_vector(_a);
    scalarV b = span_to_vector(_b);
    crypto::ec_scalar last_challenge = challenge;

    LR_V LR;
  
    while (G.size() > 1)
      {
        const auto [L, R] = init_inner_product_argument
          (
           G
           , H
           , a
           , b
           , u
           );

        const auto challenge = hash_dataV_to_scalar
          (crypto::dataV{last_challenge, to_inv8(L), to_inv8(R)});

        if (challenge == rct::s_zero)
          {
            LOG_INFO("challenge is 0, aborting");
            return {};
          }

        last_challenge = challenge;

        LR.emplace_back(L, R);

        std::tie(G, H, a, b) =
          reduce_inner_product_argument
          (
           G
           , H
           , a
           , b
           , challenge
           );
      }

    return {{ LR, a.front(), b.front() }};
  }

}
