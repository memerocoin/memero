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

#include "bulletproofs_verify.hpp"

#include "math/ringct/functional/vectorOps.hpp"
#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/functional/accumHash.hpp"

#include "tools/epee/include/logging.hpp"

namespace rct
{

  std::optional<HashChallenge> get_hash_challenges
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

    const auto challenge_x =
      *maybe_hash_challenge_z_T1_T2;

    const auto maybe_inner_product_challenge =
      maybe_hash_V_to_non_zero_scalar
      (
       crypto::dataV
       {
         challenge_x
         , challenge_x
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

    const auto maybe_hash_data_inner_product_LR_challenges =
      accum_hash(inner_product_challenge, lr_data);

    const auto hash_data_inner_product_LR_challenges =
      *maybe_hash_data_inner_product_LR_challenges;

    return {{
        challenge_y
        , challenge_z
        , challenge_x
        , inner_product_challenge
        , hash_data_inner_product_LR_challenges
      }};
  }


  bool bulletproof_VERIFY
  (
   const pointS commits
   , const Bulletproof proof
   , const pointS G_V
   , const pointS H_V
   )
  {
    LOG_ERROR_AND_RETURN_UNLESS
      (
       commits.size() >= 1
       , false
       , "commits V does not have at least one element"
       );

    LOG_ERROR_AND_RETURN_UNLESS
      (proof.LR.size() > 0, false, "Empty proof");

    LOG_ERROR_AND_RETURN_UNLESS
      (
       commits.size() <= max_outputs
       , false, "too many points for the proof"
       );

    constexpr size_t log_bit_width =
      ceiling_log2_review(bit_width).second;

    const auto
      [
       padded_number_of_inputs
       , log_padded_number_of_inputs
       ] =
      ceiling_log2_review(commits.size());

    const size_t rounds = log_padded_number_of_inputs + log_bit_width;

    LOG_ERROR_AND_RETURN_UNLESS
      (
       proof.LR.size() == rounds
       , false, "Proof is not the expected size"
       );


    const auto maybe_challenges = get_hash_challenges(commits, proof);

    LOG_ERROR_AND_RETURN_UNLESS
      (maybe_challenges, false, "invalid hash challenges");

    const auto challenges = *maybe_challenges;


    // setup weighted aggregates

    pointV L_V;
    std::transform
      (
       proof.LR.begin()
       , proof.LR.end()
       , std::back_inserter(L_V)
       , [](const auto& x) { return x.first; }
       );

    const auto L_challenges =
      hadamard_product
      (
       challenges.inner_product_LR_challenges
       , challenges.inner_product_LR_challenges
       );
       
    const auto L_commit =
      vector_commit
      (
       L_challenges
       , L_V
       );

    pointV R_V;
    std::transform
      (
       proof.LR.begin()
       , proof.LR.end()
       , std::back_inserter(R_V)
       , [](const auto& x) { return x.second; }
       );

    const scalarV w_inv_V = multiplicative_inverse_V
      (challenges.inner_product_LR_challenges);

    const auto R_challenges =
      hadamard_product
      (
       w_inv_V
       , w_inv_V
       );

    const auto R_commit =
      vector_commit
      (
       R_challenges
       , R_V
       );


    const auto challenge_z = challenges.V_A_S_rehash;
    const scalarV z_exponents = scalar_exponents
      (challenge_z, padded_number_of_inputs + 3);

    const auto z_commit =
      vector_commit
      (
       std::span(z_exponents).subspan(2, commits.size())
       , commits
       );


    const size_t total_bit_width =
      padded_number_of_inputs * bit_width;

    scalarV w_cache(total_bit_width);
    w_cache[0] = w_inv_V[0];
    w_cache[1] = challenges.inner_product_LR_challenges[0];
    for (size_t j = 1; j < rounds; ++j)
      {
        const size_t slots = 1<<(j+1);
        for (size_t s = slots; s-- > 0; --s)
          {
            w_cache[s] =
              w_cache[s/2]
              * challenges.inner_product_LR_challenges[j]
              ;

            w_cache[s-1] = w_cache[s/2] * w_inv_V[j];
          }
      }

    const auto z4_V =
      vector_add
      (
       vector_mult
       (
        w_cache
        , proof.a 
        )
       , challenge_z
       );
         
    const auto z4_commit = vector_commit(z4_V, G_V);


    auto w_cache_reverse = w_cache;
    std::reverse(w_cache_reverse.begin(), w_cache_reverse.end());

    const auto challenge_y = challenges.V_A_S;

    const auto y_exponents =
      scalar_exponents(challenge_y, total_bit_width);

    const crypto::ec_scalar y_inv =
      crypto::multiplicative_inverse(challenge_y);

    const auto y_inv_exponents =
      scalar_exponents(y_inv, total_bit_width);
    
    const auto z5_h1 =
      vector_mult
      (
       hadamard_product
       (
        y_inv_exponents
        , w_cache_reverse
        )
       , proof.b
       );

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

    const auto z5_h2 =
      vector_add_V
      (
       z_exp_mult_two_exp_flatten
       , vector_mult
       (
        y_exponents
        , challenge_z
        )
       );

    const auto z5_V =
      vector_subtract_V
      (
       z5_h1
       , hadamard_product
       (
        z5_h2
        , y_inv_exponents
        )
       );

    const auto z5_commit = vector_commit(z5_V, H_V);



    // collect
    const crypto::ec_scalar ip1y =
      sum_of_scalar_exponents(challenge_y, total_bit_width);

    const crypto::ec_scalar k1 =
      vector_sum(std::span(z_exponents).subspan(3));

    const crypto::ec_scalar ip12 = vector_sum(two_exponents);

    const crypto::ec_scalar k =
      s_zero - challenge_z * challenge_z * ip1y - k1 * ip12;

    const crypto::ec_scalar y0 = s_zero - proof.tau;
    const crypto::ec_scalar y1 =
      (proof.t - (challenge_z * ip1y + k));

    const crypto::ec_scalar z1 = proof.mu;
    const crypto::ec_scalar z3 =
      (proof.t - proof.a * proof.b)
      * challenges.inner_product_challenge
      ;

    const auto challenge_x = challenges.V_A_S_T1_T2;

    const auto T_commit = substitute_polynomial
      (
       pointV
       {
         z_commit
         , proof.T1
         , proof.T2
       }
       , challenge_x
       )
      ;

    const auto points_Y =
      pointV
      {
        T_commit
        , G_(y0)
        , H_(s_zero - y1)
      }
    ;

    const auto valid_Y = vector_sum(points_Y) == crypto::identity;

    const auto points_Z =
      pointV
      {
        crypto::identity
        , crypto::identity - L_commit
        , crypto::identity - R_commit
        , crypto::identity - proof.A
        , crypto::identity - (proof.S ^ challenge_x)
        , z4_commit
        , z5_commit
        , G_(z1)
        , H_(s_zero - z3)
      }
    ;

    const auto valid_Z = vector_sum(points_Z) == crypto::identity;

    if (valid_Y && valid_Z)
      {
        return true;
      }
    else
      {
        LOG_ERROR("Verification failure");
        return false;
      }
  }

}
