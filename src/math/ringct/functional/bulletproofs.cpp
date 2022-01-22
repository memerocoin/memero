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

#include "bulletproofs.hpp"

#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/functional/accumHash.hpp"

#include "tools/epee/include/logging.hpp"

#include <numeric>

namespace rct
{
  std::optional<proof_data_t> make_hash_challenges
  (const pointS commits, const Bulletproof proof) {

    crypto::dataV commit_data_V;
    std::transform
      (
       commits.begin()
       , commits.end()
       , std::back_inserter(commit_data_V)
       , to_inv8
       );

    const auto maybe_hash_data_V_A_S_array = accum_hash
      (
       {}
       , {
         commit_data_V
         , { to_inv8(proof.A), to_inv8(proof.S) }
       }
       );

    LOG_ERROR_AND_RETURN_UNLESS
      (maybe_hash_data_V_A_S_array
       , {}
       , "failed to generate hash challenges"
       );

    const auto hash_data_V_A_S_array = *maybe_hash_data_V_A_S_array;
    const auto hash_data_V_A_S = hash_data_V_A_S_array.back();
    const auto hash_data_V_A_S_rehash =
      rct::hash_to_scalar(hash_data_V_A_S);

    LOG_ERROR_AND_RETURN_IF((hash_data_V_A_S == rct::s_zero), {}, "z == 0");

    const auto hash_data_V_A_S_rehash_T1_T2 =
      hash_dataV_to_scalar
      (
       crypto::dataV
       {
         hash_data_V_A_S_rehash
         , hash_data_V_A_S_rehash
         , to_inv8(proof.T1)
         , to_inv8(proof.T2)
       }
       );

    LOG_ERROR_AND_RETURN_IF
      (
       (hash_data_V_A_S_rehash_T1_T2 == rct::s_zero)
       , {}
       , "x == 0"
       );

    const auto inner_product_challenge =
      hash_dataV_to_scalar
      (
       crypto::dataV
       {
         hash_data_V_A_S_rehash_T1_T2
         , hash_data_V_A_S_rehash_T1_T2
         , proof.taux
         , proof.mu
         , proof.t
       });

    LOG_ERROR_AND_RETURN_IF((inner_product_challenge == rct::s_zero), {}, "inner_product_challenge == 0");

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

    LOG_ERROR_AND_RETURN_UNLESS
      (
       maybe_hash_data_inner_product_challenge_LR
       , {}
       , "some w[i] == 0"
       );

    const auto hash_data_inner_product_challenge_LR =
      *maybe_hash_data_inner_product_challenge_LR;

    return {{
        hash_data_V_A_S_rehash_T1_T2
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

}
