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
#include "math/ringct/functional/innerProductArgument_verify.hpp"

#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/logging_macro.hpp"

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


    return {{
        challenge_y
        , challenge_z
        , challenge_x
        , inner_product_challenge
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


    // 1. check blinding terms

    const crypto::ec_point blinding_terms_commit_L =
      H_(proof.t) + G_(proof.tau);

    const size_t total_bit_width =
      padded_number_of_inputs * bit_width;

    const auto z = challenges.V_A_S_rehash;
    const auto y = challenges.V_A_S;

    const auto delta_1 = (z - (z * z)) *
      sum_of_scalar_exponents(y, total_bit_width);

    const scalarV z_exponents = scalar_exponents
      (z, padded_number_of_inputs + 3);

    const crypto::ec_scalar z_sum_skip_3 = vector_sum
      (std::span(z_exponents).subspan(3, padded_number_of_inputs));

    const crypto::ec_scalar delta_2 =
      z_sum_skip_3 * sum_of_scalar_exponents(crypto::s_2, bit_width);

    const auto delta = delta_1 - delta_2;

    const auto coefficient_T_0 = H_(delta)
      + vector_commit
      (
       std::span(z_exponents).subspan(2, commits.size())
       , commits
       );

    const auto challenge_x = challenges.V_A_S_T1_T2;

    const crypto::ec_point blinding_terms_commit_R =
      substitute_polynomial
      (
       pointV
       {
         coefficient_T_0
         , proof.T1
         , proof.T2
       }
       , challenge_x
       );

       
    if (blinding_terms_commit_L != blinding_terms_commit_R) {
      LOG_ERROR("Invalid commits of blinding terms");
      return false;
    }


    // 2. check inner product argument
    
    const auto challenge_z = challenges.V_A_S_rehash;
    const auto challenge_y = challenges.V_A_S;

    const auto y_exponents =
      scalar_exponents(challenge_y, total_bit_width);

    const crypto::ec_scalar y_inv =
      crypto::multiplicative_inverse(challenge_y);

    const auto y_inv_exponents =
      scalar_exponents(y_inv, total_bit_width);

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

    const auto P_G =
      vector_commit
      (
       scalar_repeat(s_zero - challenge_z, total_bit_width)
       , G_V
       );

    // I = H'
    const auto I_V = vector_multP_V(y_inv_exponents, H_V);

    const auto P_I_scalars =
      vector_add_V
      (
       z_exp_mult_two_exp_flatten
       , vector_mult
       ( y_exponents
         , challenge_z
         )
       );

    const auto P_I = vector_commit(P_I_scalars, I_V);

    const auto u = H_(challenges.inner_product_challenge);

    const auto P =
      vector_sum
      (
       pointV
       {
         proof.A
         , (proof.S ^ challenge_x)
         , P_G
         , P_I
         , (u ^ proof.t)
         , G_(s_zero - proof.mu)
       }
       );

    const RecursiveInnerProductArgument ipa =
      {
        P
        , span_to_vector(G_V.subspan(0, total_bit_width))
        , I_V
        , proof.LR
        , proof.a
        , proof.b
        , u
      };

    const auto is_valid_ipa =
      verify_recursive_inner_product_argument
      (
       ipa
       , challenges.inner_product_challenge
       );

    if (is_valid_ipa)
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
