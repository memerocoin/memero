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

#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/functional/vectorOps.hpp"
#include "math/ringct/functional/accumHash.hpp"

#include "tools/common/varint.h"
#include "tools/epee/include/string_tools.h"
#include "tools/epee/include/logging.hpp"

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
    return get_bp_generator(H, idx * 2 + 1);
  }

  crypto::ec_point get_bp_generator_H(const size_t idx) {
    return get_bp_generator(H, idx * 2);
  }

  pointV get_bp_generator_G_V(const size_t idx) {
    pointV xs(idx);
    std::generate
      (
       xs.begin()
       , xs.end()
       , [i = 0] () mutable {
         const auto r = get_bp_generator_G(i);
         i++;
         return r;
       }
       );

    return xs;
  }
    
  pointV get_bp_generator_H_V(const size_t idx) {
    pointV xs(idx);
    std::generate
      (
       xs.begin()
       , xs.end()
       , [i = 0] () mutable {
         const auto r = get_bp_generator_H(i);
         i++;
         return r;
       }
       );

    return xs;
  }


  std::optional
  <std::tuple
   <
     crypto::ec_scalar
     , crypto::ec_scalar
     >>
  hash_V_A_S
  (
   const pointS commits
   , const crypto::ec_point x
   , const crypto::ec_point y
   )
  {
    crypto::dataV commit_data_V;
    std::transform
      (
       commits.begin()
       , commits.end()
       , std::back_inserter(commit_data_V)
       , to_inv8
       );

    const auto maybe_hash_data_commit =
      maybe_hash_V_to_non_zero_scalar(commit_data_V);

    if (!maybe_hash_data_commit) {
      return {};
    }
    const auto hash_data_commit = *maybe_hash_data_commit;

    const auto maybe_challenge_y =
      maybe_hash_V_to_non_zero_scalar
      (
       crypto::dataV
       {
         hash_data_commit
         , to_inv8(x)
         , to_inv8(y)
       }
       );

    if (!maybe_challenge_y) {
      return {};
    }

    const auto challenge_y = *maybe_challenge_y;
    const auto maybe_challenge_z =
      maybe_hash_V_to_non_zero_scalar(crypto::dataV{challenge_y});

    if (!maybe_challenge_z) {
      return {};
    }

    const auto challenge_z =
      *maybe_challenge_z;

    return {{challenge_y, challenge_z}};
  }

  std::optional<hash_data_t> make_hash_challenges
  (const pointS commits, const Bulletproof proof)
  {
    const auto maybe_hash_V_A_S =
      hash_V_A_S(commits, proof.A, proof.S);

    if (!maybe_hash_V_A_S) {
      return {};
    }

    const auto [challenge_y, challenge_z] =
      *maybe_hash_V_A_S;

    const auto maybe_hash_challenge_z_T1_T2 =
      maybe_hash_V_to_non_zero_scalar
      (
       crypto::dataV
       {
         challenge_z
         , challenge_z
         , to_inv8(proof.T1)
         , to_inv8(proof.T2)
       }
       );

    if (!maybe_hash_challenge_z_T1_T2) {
      return {};
    }

    const auto hash_challenge_z_T1_T2 =
      *maybe_hash_challenge_z_T1_T2;

    const auto maybe_inner_product_challenge =
      maybe_hash_V_to_non_zero_scalar
      (
       crypto::dataV
       {
         hash_challenge_z_T1_T2
         , hash_challenge_z_T1_T2
         , proof.tau
         , proof.mu
         , proof.t
       });

    if (!maybe_inner_product_challenge) {
      return {};
    }

    const auto inner_product_challenge =
      *maybe_inner_product_challenge;


    std::vector<std::vector<crypto::crypto_data>> lr_data;
    std::transform
      (
       proof.LR.begin()
       , proof.LR.end()
       , std::back_inserter(lr_data)
       , []
       (
        const auto lr
        ) -> std::vector<crypto::crypto_data> {
         return {to_inv8(lr.first), to_inv8(lr.second)};
       }
       );

    const auto maybe_hash_data_inner_product_challenge_LR =
      accum_hash(inner_product_challenge, lr_data);

    const auto hash_data_inner_product_challenge_LR =
      *maybe_hash_data_inner_product_challenge_LR;

    return {{
        challenge_y
        , challenge_z
        , hash_challenge_z_T1_T2
        , inner_product_challenge
        , hash_data_inner_product_challenge_LR
      }};
  }

  scalarV int_to_bits(const uint64_t x) {
    constexpr size_t bit_length = sizeof(uint64_t) * 8;
    scalarV xs;

    std::generate_n
      (
       std::back_inserter(xs)
       , bit_length
       , [x, i = 1ull] () mutable {
         const auto bit =
           (x & i) > 0
           ? crypto::s_1
           : crypto::s_0
           ;

         i = i << 1;

         return bit;
       }
       );

    return xs;
  }

  std::optional
  <std::tuple
   <
     scalarV
     , scalarV
     , crypto::ec_scalar
     , crypto::ec_scalar
     , crypto::ec_point
     , crypto::ec_point
     , crypto::ec_point
     , crypto::ec_point
     , crypto::ec_scalar
     , crypto::ec_scalar
     >>
  get_bp_vectors_for_inner_product_argument
  (
   const std::span<const bp_input_t> xs
   , const crypto::ec_scalar alpha
   , const scalarS sL
   , const scalarS sR
   , const crypto::ec_scalar rho
   , const crypto::ec_scalar tau1
   , const crypto::ec_scalar tau2
   ) {

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

    const auto padded_number_of_inputs =
      ceiling_log2_review(xs.size()).first;

    const size_t total_bit_width =
      padded_number_of_inputs * bit_width;

    std::generate_n
      (
       std::back_inserter(bits)
       , padded_number_of_inputs - xs.size()
       , []() { return scalar_repeat(crypto::s_0, bit_width); }
       );

    const scalarV aL = vector_concat(bits);
    const scalarV aR = vector_subtract(aL, crypto::s_1);

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

    const auto G_V = get_bp_generator_G_V(total_bit_width);
    const auto H_V = get_bp_generator_H_V(total_bit_width);

    const crypto::ec_point A =
      vector_commit(aL, G_V) + vector_commit(aR, H_V) + G_(alpha);

    const crypto::ec_point S =
      vector_commit(sL, G_V) + vector_commit(sR, H_V) + G_(rho);


    const auto maybe_challenge_y = hash_V_A_S(V, A, S);

    if (!maybe_challenge_y) {
      return {};
    }

    const auto [challenge_y, challenge_z] =
      *maybe_challenge_y;


    const scalarV l0 = vector_subtract(aL, challenge_z);
    const scalarS l1 = sL;

    const auto y_exponents =
      scalar_exponents(challenge_y, total_bit_width);

    const scalarV z_exponents = scalar_exponents
      (challenge_z, padded_number_of_inputs + 2);

    const scalarV two_exponents =
      scalar_exponents(rct::s_two, bit_width);

    const std::vector<scalarV> z_exp_mult_two_exp_monadic =
      vector_mult_V_monadic
      (
       std::span(z_exponents).subspan(2, padded_number_of_inputs)
       , two_exponents
       );

    const scalarV z_exp_mult_two_exp_flatten =
      vector_concat(z_exp_mult_two_exp_monadic);

    const scalarV r0 = vector_add_V
      (
       hadamard_product
       (
        y_exponents
        , vector_add(aR, challenge_z)
        )
       , z_exp_mult_two_exp_flatten
       );

    const scalarV r1 = hadamard_product(y_exponents, sR);

    const crypto::ec_scalar t1 =
      inner_product(l0, r1) + inner_product(l1, r0);

    const crypto::ec_scalar t2 = inner_product(l1, r1);


    const crypto::ec_point T1 = G_(tau1) + H_(t1);
    const crypto::ec_point T2 = G_(tau2) + H_(t2);

    const auto maybe_hash_challenge_z_T1_T2 =
      maybe_hash_V_to_non_zero_scalar
      (
       crypto::dataV
       {
         challenge_z
         , challenge_z
         , to_inv8(T1)
         , to_inv8(T2)
       }
       );

    if (!maybe_hash_challenge_z_T1_T2) {
      return {};
    }

    const auto challenge_x =
      *maybe_hash_challenge_z_T1_T2;

    scalarV blinding_factors;
    std::transform
      (
       xs.begin()
       , xs.end()
       , std::back_inserter(blinding_factors)
       , [](const auto& x ) { return x.second; }
       );

    const crypto::ec_scalar tau0 =
      inner_product
      (
       blinding_factors
       , std::span(z_exponents).subspan(2)
       );

    const auto x = challenge_x;
    const crypto::ec_scalar tau = substitute_polynomial
      (scalarV{tau0, tau1, tau2}, x);

    const crypto::ec_scalar mu = x * rho + alpha;

    const scalarV l = vector_add_V(l0, vector_mult(l1, x));
    const scalarV r = vector_add_V(r0, vector_mult(r1, x));

    const crypto::ec_scalar t = inner_product(l, r);

    const auto maybe_inner_product_challenge =
      maybe_hash_V_to_non_zero_scalar
      (
       crypto::dataV
       {
         x
         , x
         , tau
         , mu
         , t
       }
       );

    if (!maybe_inner_product_challenge) {
      return {};
    }

    const auto inner_product_challenge =
      *maybe_inner_product_challenge;

    return {{
        l
        , r
        , inner_product_challenge
        , challenge_y
        , A
        , S
        , T1
        , T2
        , tau
        , mu
      }};
  }

}
