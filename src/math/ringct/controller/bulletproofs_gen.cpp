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
#include "math/ringct/functional/accumHash.hpp"

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

  crypto::ec_point commit_vectors_with_bp_generators_G_H
  (
   const scalarS a
   , const scalarS b
   )
  {
    LOG_ERROR_AND_THROW_UNLESS
      (a.size() == b.size(), "Incompatible sizes of a and b");

    LOG_ERROR_AND_THROW_UNLESS
      (a.size() <= max_vector_length, "vector size too big");

    return vector_commit(a, G_V) + vector_commit(b, H_V);
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

    pointV V;
    std::transform
      (
       xs.begin()
       , xs.end()
       , std::back_inserter(V)
       , [](const auto& x) {
         return std::apply(commit, x);
       }
       );

    // PAPER LINES 41-42
    std::vector<scalarV> bits;
    std::transform
      (
       xs.begin()
       , xs.end()
       , std::back_inserter(bits)
       , [](const auto& x) -> scalarV {
         return int_to_bits(x.first);
       }
       );

    std::generate_n
      (
       std::back_inserter(bits)
       , padded_number_of_inputs - xs.size()
       , []() { return scalar_repeat(crypto::s_0, bit_width); }
       );

    const scalarV aL = vector_concat(bits);
    const scalarV aR = vector_subtract(aL, crypto::s_1);

  try_again:
    // PAPER LINES 43-44
    const crypto::ec_scalar alpha = crypto::randomScalar();
    const crypto::ec_point A =
      commit_vectors_with_bp_generators_G_H(aL, aR) + G_(alpha);

    // PAPER LINES 45-47
    const scalarV sL = crypto::randomScalars(total_bit_width);
    const scalarV sR = crypto::randomScalars(total_bit_width);
    const crypto::ec_scalar rho = crypto::randomScalar();
    const crypto::ec_point S =
      commit_vectors_with_bp_generators_G_H(sL, sR) + G_(rho);

    const auto maybe_hash_data_V_A_S = hash_V_A_S(V, A, S);

    if (!maybe_hash_data_V_A_S) {
      goto try_again;
    }

    const auto [hash_data_V_A_S, hash_data_V_A_S_rehash] =
      *maybe_hash_data_V_A_S;

    // Polynomial construction by coefficients
    // PAPER LINES 70-71
    const scalarV l0 = vector_subtract(aL, hash_data_V_A_S_rehash);
    const scalarS l1 = sL;

    const scalarV z_exponents = scalar_exponents
      (hash_data_V_A_S_rehash, padded_number_of_inputs + 2);

    const scalarS z_exponents_skip_2 =
      std::span(z_exponents).subspan(2);

    const scalarV two_exponents =
      scalar_exponents(rct::s_two, bit_width);

    std::vector<scalarV> zero_twos;
    std::transform
      (
       z_exponents_skip_2.begin()
       , z_exponents_skip_2.end()
       , std::back_inserter(zero_twos)
       , [two_exponents](const auto& x) -> scalarV {
         return vector_mult(two_exponents, x);
       }
       );

    const auto y_exponents =
      scalar_exponents(hash_data_V_A_S, total_bit_width);

    const scalarV r0 = vector_add_V
      (
       hadamard_product
       (vector_add(aR, hash_data_V_A_S_rehash), y_exponents)
       , vector_concat(zero_twos)
       );

    const scalarV r1 = hadamard_product(y_exponents, sR);

    // Polynomial construction before PAPER LINE 51
    const crypto::ec_scalar t1 =
      inner_product(l0, r1) + inner_product(l1, r0);

    const crypto::ec_scalar t2 = inner_product(l1, r1);

    // PAPER LINES 52-53
    const crypto::ec_scalar tau1 = crypto::randomScalar();
    const crypto::ec_scalar tau2 = crypto::randomScalar();

    const crypto::ec_point T1 = G_(tau1) + H_(t1);
    const crypto::ec_point T2 = G_(tau2) + H_(t2);

    // PAPER LINES 54-56
    const crypto::ec_scalar hash_data_V_A_S_rehash_T1_T2 =
      hash_dataV_to_scalar
      (
       crypto::dataV
       {
         hash_data_V_A_S_rehash
         , hash_data_V_A_S_rehash
         , to_inv8(T1)
         , to_inv8(T2)
       }
       );

    if (hash_data_V_A_S_rehash_T1_T2 == rct::s_zero)
      {
        LOG_INFO("hash_data_V_A_S_rehash_T1_T2 is 0, trying again");
        goto try_again;
      }

    // PAPER LINES 61-63
    LOG_ERROR_AND_THROW_UNLESS
      (
       xs.size() <= z_exponents_skip_2.size()
       , "invalid z_exponents_skip_2 length"
       );

    scalarV blinding_factors;
    std::transform
      (
       xs.begin()
       , xs.end()
       , std::back_inserter(blinding_factors)
       , [](const auto& x ) { return x.second; }
       );

    const crypto::ec_scalar taux1 =
      inner_product(blinding_factors, z_exponents_skip_2);

    const auto x = hash_data_V_A_S_rehash_T1_T2;
    const crypto::ec_scalar taux = tau1 * x + tau2 * x * x + taux1;

    const crypto::ec_scalar mu = x * rho + alpha;

    // PAPER LINES 58-60
    const scalarV l = vector_add_V(l0, vector_mult(l1, x));
    const scalarV r = vector_add_V(r0, vector_mult(r1, x));

    const crypto::ec_scalar t = inner_product(l, r);

    // PAPER LINE 6
    const crypto::ec_scalar inner_product_challenge =
      hash_dataV_to_scalar(crypto::dataV{x, x, taux, mu, t});

    if (inner_product_challenge == rct::s_zero)
      {
        LOG_INFO("inner_product_challenge is 0, trying again");
        goto try_again;
      }

    const crypto::ec_scalar y_inv =
      crypto::multiplicative_inverse(hash_data_V_A_S);

    const scalarV y_inv_exponents =
      scalar_exponents(y_inv, total_bit_width);

    const auto maybe_recursive_inner_product_argument =
      make_recursive_inner_product_argument
      (
       std::span(G_V).subspan(0, total_bit_width)
       , vector_multP_V(y_inv_exponents, H_V)
       , l
       , r
       , H_(inner_product_challenge)
       , inner_product_challenge
       );

    if (!maybe_recursive_inner_product_argument) {
      goto try_again;
    }

    const auto [LR, a, b] = *maybe_recursive_inner_product_argument;

    return Bulletproof
      {
        A, S, T1, T2, taux, mu, LR, a, b, t
      };
  }

}
