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

Adapted from C++ code from The Monero Project
Adapted from Java code by Sarang Noether
Paper references are to https://eprint.iacr.org/2017/1066
(revision 1 July 2018)

*/


#include "bulletproofs_gen.hpp"

#include "math/ringct/functional/vectorOps.hpp"
#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/functional/bulletproofs.hpp"
#include "math/ringct/functional/innerProductArgument.hpp"

#include "math/crypto/controller/keyGen.hpp"

#include "tools/epee/include/logging.hpp"

namespace rct
{
  Bulletproof bulletproof_MAKE(const std::span<const bp_input_t> xs)
  {
    LOG_ERROR_AND_THROW_UNLESS(!xs.empty(), "Nothing to proof");
    LOG_ERROR_AND_THROW_UNLESS
      (xs.size() <= max_outputs, "too many amounts to proof");

    for (const auto& [x,g]: xs) {
      LOG_ERROR_AND_THROW_UNLESS
        (is_reduced(g), "Invalid blinding factor");
    }

    const auto padded_number_of_inputs = ceiling_log2_review(xs.size()).first;
    const size_t total_bit_width =
      padded_number_of_inputs * bit_width;

    while (true) {

      const crypto::ec_scalar alpha = crypto::randomScalar();
      const scalarV sL = crypto::randomScalars(total_bit_width);
      const scalarV sR = crypto::randomScalars(total_bit_width);
      const crypto::ec_scalar rho = crypto::randomScalar();
      const crypto::ec_scalar tau1 = crypto::randomScalar();
      const crypto::ec_scalar tau2 = crypto::randomScalar();

      const auto bp_vectors =
        get_bp_vectors_for_inner_product_argument
        (
         xs
         , alpha
         , sL
         , sR
         , rho
         , tau1
         , tau2
         );

      if (!bp_vectors) {
        continue;
      }

      const auto
        [
         bp_vector_l
         , bp_vector_r
         , inner_product_challenge
         , challenge_y
         , A
         , S
         , T1
         , T2
         , taux
         , mu
         ] = *bp_vectors;

    const crypto::ec_scalar challenge_y_inv =
      crypto::multiplicative_inverse(challenge_y);

      const scalarV challenge_y_inv_exponents =
        scalar_exponents(challenge_y_inv, total_bit_width);

      const auto G_V = get_bp_generator_G_V(total_bit_width);
      const auto H_V = get_bp_generator_H_V(total_bit_width);

      const auto maybe_recursive_inner_product_argument =
        make_recursive_inner_product_argument
        (
         G_V
         , vector_multP_V(challenge_y_inv_exponents, H_V)
         , bp_vector_l
         , bp_vector_r
         , H_(inner_product_challenge)
         , inner_product_challenge
         );

      if (!maybe_recursive_inner_product_argument) {
        continue;
      }

      const auto ipa = *maybe_recursive_inner_product_argument;

      return Bulletproof
        {
          A, S, T1, T2, taux, mu, ipa.LR, ipa.a, ipa.b
          , inner_product(bp_vector_l, bp_vector_r)
        };

    }
  }

}
