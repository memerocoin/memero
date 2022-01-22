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

#include "bulletproofs.hpp"

#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/functional/vectorOps.hpp"
#include "math/ringct/functional/accumHash.hpp"

#include "tools/epee/include/logging.hpp"

#include <numeric>

namespace rct
{
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

    const auto maybe_hash_data_V_A_S =
      maybe_hash_V_to_non_zero_scalar
      (
       crypto::dataV
       {
         hash_data_commit
         , to_inv8(x)
         , to_inv8(y)
       }
       );

    if (!maybe_hash_data_V_A_S) {
      return {};
    }

    const auto hash_data_V_A_S = *maybe_hash_data_V_A_S;
    const auto maybe_hash_data_V_A_S_rehash =
      maybe_hash_V_to_non_zero_scalar(crypto::dataV{hash_data_V_A_S});

    if (!maybe_hash_data_V_A_S_rehash) {
      return {};
    }

    const auto hash_data_V_A_S_rehash =
      *maybe_hash_data_V_A_S_rehash;

    return {{hash_data_V_A_S, hash_data_V_A_S_rehash}};
  }

  std::optional<proof_data_t> make_hash_challenges
  (const pointS commits, const Bulletproof proof)
  {
    const auto maybe_hash_data_V_A_S =
      hash_V_A_S(commits, proof.A, proof.S);

    if (!maybe_hash_data_V_A_S) {
      return {};
    }

    const auto [hash_data_V_A_S, hash_data_V_A_S_rehash] =
      *maybe_hash_data_V_A_S;

    const auto maybe_hash_data_V_A_S_T1_T2 =
      maybe_hash_V_to_non_zero_scalar
      (
       crypto::dataV
       {
         hash_data_V_A_S_rehash
         , hash_data_V_A_S_rehash
         , to_inv8(proof.T1)
         , to_inv8(proof.T2)
       }
       );

    if (!maybe_hash_data_V_A_S_T1_T2) {
      return {};
    }

    const auto hash_data_V_A_S_T1_T2 =
      *maybe_hash_data_V_A_S_T1_T2;

    const auto maybe_inner_product_challenge =
      maybe_hash_V_to_non_zero_scalar
      (
       crypto::dataV
       {
         hash_data_V_A_S_T1_T2
         , hash_data_V_A_S_T1_T2
         , proof.taux
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
        hash_data_V_A_S_T1_T2
        , hash_data_V_A_S
        , hash_data_V_A_S_rehash
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
     , crypto::ec_scalar
     >>
  get_bp_vectors_for_inner_product_argument
  (
    const pointS V
    , const scalarS blinding_factors
    , const size_t padded_number_of_inputs
    , const size_t bit_width
    , const size_t total_bit_width
    , const scalarS aL
    , const scalarS aR
    , const crypto::ec_scalar alpha
    , const scalarS sL
    , const scalarS sR
    , const crypto::ec_scalar rho
    , const crypto::ec_scalar tau1
    , const crypto::ec_scalar tau2
    , const pointS G_V
    , const pointS H_V
   ) {

   // PAPER LINES 43-44
    const crypto::ec_point A =
      vector_commit(aL, G_V) + vector_commit(aR, H_V) + G_(alpha);

    const crypto::ec_point S =
      vector_commit(sL, G_V) + vector_commit(sR, H_V) + G_(rho);

    // PAPER LINES 45-47
    const auto maybe_hash_data_V_A_S = hash_V_A_S(V, A, S);

    if (!maybe_hash_data_V_A_S) {
      return {};
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

    const crypto::ec_point T1 = G_(tau1) + H_(t1);
    const crypto::ec_point T2 = G_(tau2) + H_(t2);

    // PAPER LINES 54-56
    const auto maybe_hash_data_V_A_S_T1_T2 =
      maybe_hash_V_to_non_zero_scalar
      (
       crypto::dataV
       {
         hash_data_V_A_S_rehash
         , hash_data_V_A_S_rehash
         , to_inv8(T1)
         , to_inv8(T2)
       }
       );

    if (!maybe_hash_data_V_A_S_T1_T2) {
      return {};
    }

    const auto hash_data_V_A_S_T1_T2 =
      *maybe_hash_data_V_A_S_T1_T2;

    // PAPER LINES 61-63
    LOG_ERROR_AND_THROW_UNLESS
      (
       V.size() <= z_exponents_skip_2.size()
       , "invalid z_exponents_skip_2 length"
       );

    const crypto::ec_scalar taux1 =
      inner_product(blinding_factors, z_exponents_skip_2);

    const auto x = hash_data_V_A_S_T1_T2;
    const crypto::ec_scalar taux = tau1 * x + tau2 * x * x + taux1;

    const crypto::ec_scalar mu = x * rho + alpha;

    // PAPER LINES 58-60
    const scalarV l = vector_add_V(l0, vector_mult(l1, x));
    const scalarV r = vector_add_V(r0, vector_mult(r1, x));

    const crypto::ec_scalar t = inner_product(l, r);

    // PAPER LINE 6
    const auto maybe_inner_product_challenge =
      maybe_hash_V_to_non_zero_scalar
      (
       crypto::dataV
       {
         x
         , x
         , taux
         , mu
         , t
       }
       );

    if (!maybe_inner_product_challenge) {
      return {};
    }

    const auto inner_product_challenge =
      *maybe_inner_product_challenge;

    const crypto::ec_scalar y_inv =
      crypto::multiplicative_inverse(hash_data_V_A_S);

    return {{
        l
        , r
        , inner_product_challenge
        , y_inv
        , A
        , S
        , T1
        , T2
        , taux
        , mu
        , t
      }};
  }

}
