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


#include "innerProductArgument_verify.hpp"

#include "math/ringct/functional/vectorOps.hpp"
#include "math/ringct/functional/rctOps.hpp"

#include "tools/epee/include/logging.hpp"

namespace rct
{
  crypto::ec_point verify_half
  (
   const crypto::ec_point P
   , const crypto::ec_point L
   , const crypto::ec_point R
   , const crypto::ec_scalar challenge
   )
  {
    const auto x = challenge;
    const auto x_inv = multiplicative_inverse(x);

    const auto p =
      (L ^ (x * x))
      + P
      + (R ^ (x_inv * x_inv))
      ;

    return p;
  }

  bool verify_inner_product_argument
  (
   const InnerProductArgument ipa
   , const crypto::ec_scalar challenge
   , const scalarS a_half
   , const scalarS b_half
   )
  {
    const auto x = challenge;
    const auto x_inv = multiplicative_inverse(x);

    const auto h = homomorphic_hash_full
      (
       ipa.G
       , ipa.H
       , vector_mult(a_half, x_inv)
       , vector_mult(a_half, x)
       , vector_mult(b_half, x)
       , vector_mult(b_half, x_inv)
       , ipa.u
       , inner_product(a_half, b_half)
       );

    const auto p = verify_half(ipa.P, ipa.L, ipa.R, x);

    return h == p;
  }

  bool verify_recursive_inner_product_argument
  (
   const RecursiveInnerProductArgument ipa
   , const crypto::ec_scalar challenge
   )
  {
    if (ipa.LR.empty()) {
      LOG_FATAL("ipa.LR shouldn't be emtpy");
      return false;
    }

    const auto [L,R] = ipa.LR.front(); 
    const auto maybe_new_challenge = maybe_hash_V_to_non_zero_scalar
      (crypto::dataV{challenge, to_inv8(L), to_inv8(R)});

    if (!maybe_new_challenge) {
      return false;
    }

    const auto new_challenge = *maybe_new_challenge;

    if (ipa.LR.size() == 1) {

      const auto ipa_one = InnerProductArgument
        {
          ipa.P
          , ipa.G
          , ipa.H
          , L
          , R
          , ipa.u
        };

      return verify_inner_product_argument
        (
         ipa_one
         , new_challenge
         , scalarV{ipa.a}
         , scalarV{ipa.b}
         );
    }

    const auto [G_half, H_half] =
      split_generators_with_challenge
      (
       ipa.G
       , ipa.H
       , new_challenge
       );

    const auto new_LR =
      LR_V(std::next(ipa.LR.begin(), 1), ipa.LR.end());

    const RecursiveInnerProductArgument new_ipa = 
      {
        verify_half(ipa.P, L, R, new_challenge)
        , G_half
        , H_half
        , new_LR
        , ipa.a
        , ipa.b
        , ipa.u
      };

    return verify_recursive_inner_product_argument
      (
       new_ipa
       , new_challenge
       );
  }
}
