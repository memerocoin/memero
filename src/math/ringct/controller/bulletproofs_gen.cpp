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
#include "math/ringct/functional/curveConstants.hpp"
#include "math/ringct/functional/bulletproofs.hpp"
#include "math/ringct/functional/innerProductArgument.hpp"

#include "math/crypto/controller/keyGen.hpp"

#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/string_tools.h"
#include "tools/common/varint.h"

#include <atomic>
#include <numeric>


namespace rct
{
  crypto::ec_point get_bp_generator
  (
   const crypto::ec_point base
   , const size_t idx
   )
  {
    constexpr std::string_view domain_separator =
      config::HASH_KEY_BULLETPROOF_EXPONENT;

    const std::string hashed =
      epee::string_tools::blob_to_string(base.data)
      + std::string(domain_separator)
      + tools::get_varint_data(idx);

    const crypto::ec_point e = crypto::hash_to_point_via_field
      (
       crypto::h2d
       (
        crypto::sha3(epee::string_tools::string_to_blob(hashed))
        )
       );

    LOG_ERROR_AND_THROW_IF
      ((e == crypto::identity), "Invalid exponent");

    return e;
  }

  crypto::ec_point get_bp_generator_G(const size_t idx) {
    return get_bp_generator(H, idx * 2);
  }

  crypto::ec_point get_bp_generator_H(const size_t idx) {
    return get_bp_generator(H, idx * 2 + 1);
  }

  std::array<crypto::ec_point, bit_width * max_outputs> G_V;
  std::array<crypto::ec_point, bit_width * max_outputs> H_V;

  std::atomic<bool> init_done(false);
  std::mutex init_mutex;

  void init_generators()
  {
    if (!init_done) {
      std::lock_guard<std::mutex> lock(init_mutex);
      std::generate
        (
         H_V.begin()
         , H_V.end()
         , [i = 0] () mutable {
           const auto r = get_bp_generator_G(i);
           i++;
           return r;
         }
         );

      std::generate
        (
         G_V.begin()
         , G_V.end()
         , [i = 0] () mutable {
           const auto r = get_bp_generator_H(i);
           i++;
           return r;
         }
         );

      init_done = true;
    }
  }

  Bulletproof bulletproof_MAKE(const std::span<const bp_input_t> xs)
  {
    LOG_ERROR_AND_THROW_UNLESS(!xs.empty(), "Nothing to proof");
    LOG_ERROR_AND_THROW_UNLESS
      (xs.size() <= max_outputs, "too many amounts to proof");

    for (const auto& [x,g]: xs) {
      LOG_ERROR_AND_THROW_UNLESS
        (is_reduced(g), "Invalid blinding factor");
    }

    init_generators();

    const auto padded_number_of_inputs = log2bound(xs.size()).first;
    const size_t total_bit_width =
      padded_number_of_inputs * bit_width;

  try_again:
    const crypto::ec_scalar alpha = crypto::randomScalar();
    const scalarV sL = crypto::randomScalars(total_bit_width);
    const scalarV sR = crypto::randomScalars(total_bit_width);
    const crypto::ec_scalar rho = crypto::randomScalar();
    const crypto::ec_scalar tau1 = crypto::randomScalar();
    const crypto::ec_scalar tau2 = crypto::randomScalar();

    const auto bp_vectors = get_bp_vectors_for_inner_product_argument
      (
       xs
       , alpha
       , sL
       , sR
       , rho
       , tau1
       , tau2
       , G_V
       , H_V
       );

    if (!bp_vectors) {
      goto try_again;
    }

    const auto
      [
       bp_vector_l
       , bp_vector_r
       , inner_product_challenge
       , y_inv
       , A
       , S
       , T1
       , T2
       , taux
       , mu
       ] = *bp_vectors;

    const scalarV y_inv_exponents =
      scalar_exponents(y_inv, total_bit_width);

    const auto maybe_recursive_inner_product_argument =
      make_recursive_inner_product_argument
      (
       std::span(G_V).subspan(0, total_bit_width)
       , vector_multP_V(y_inv_exponents, H_V)
       , bp_vector_l
       , bp_vector_r
       , H_(inner_product_challenge)
       , inner_product_challenge
       );

    if (!maybe_recursive_inner_product_argument) {
      goto try_again;
    }

    const auto [LR, a, b] = *maybe_recursive_inner_product_argument;

    return Bulletproof
      {
        A, S, T1, T2, taux, mu, LR, a, b
        , inner_product(bp_vector_l, bp_vector_r)
      };
  }

}
