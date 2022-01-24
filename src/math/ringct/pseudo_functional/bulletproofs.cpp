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

#include "math/ringct/functional/vectorOps.hpp"
#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/functional/bulletproofs.hpp"
#include "math/ringct/functional/curveConstants.hpp"
#include "math/ringct/functional/multi_exponentiation.hpp"

#include "math/crypto/controller/keyGen.hpp"

#include "tools/epee/include/logging.hpp"

#include <atomic>

namespace rct
{
  const auto multiexp = dummy;

  std::array<crypto::ec_point, max_vector_length> G_V;
  std::array<crypto::ec_point, max_vector_length> H_V;

  std::atomic<bool> init_done(false);
  std::mutex init_mutex;

  void init_generators()
  {
    if (!init_done) {
      std::lock_guard<std::mutex> lock(init_mutex);

      const auto Gs = get_bp_generator_G_V(G_V.size());
      std::copy
        (
         Gs.begin()
         , Gs.end()
         , G_V.begin()
         );

      const auto Hs = get_bp_generator_H_V(H_V.size());
      std::copy
        (
         Hs.begin()
         , Hs.end()
         , H_V.begin()
         );

      init_done = true;
    }
  }

  bool bulletproof_VERIFY
  (
   const pointS commits
   , const Bulletproof proof
   )
  {
    init_generators();

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


    const auto maybe_challenges =
      make_hash_challenges(commits, proof);

    LOG_ERROR_AND_RETURN_UNLESS
      (maybe_challenges, false, "invalid hash challenges");

    const auto challenges = *maybe_challenges;

    std::vector<MultiexpData> multiexp_data;

    // setup weighted aggregates

    const scalarV winv = multiplicative_inverse_V
      (challenges.inner_product_challenge_LR);

    const auto challenge_y = challenges.V_A_S;
    const crypto::ec_scalar yinv =
      crypto::multiplicative_inverse(challenge_y);

    const crypto::ec_scalar weight_y = crypto::randomScalar();
    const crypto::ec_scalar weight_z = crypto::randomScalar();

    std::transform
      (
       challenges.inner_product_challenge_LR.begin()
       , challenges.inner_product_challenge_LR.end()
       , proof.LR.begin()
       , std::back_inserter(multiexp_data)
       , [weight_z](const auto& w, const auto& lr) -> MultiexpData {
         return {w * w * weight_z, lr.first};
       }
       );

    std::transform
      (
       winv.begin()
       , winv.end()
       , proof.LR.begin()
       , std::back_inserter(multiexp_data)
       , [weight_z](const auto& w, const auto& lr) -> MultiexpData {
         return {w * w * weight_z, lr.second};
       }
       );

    const size_t total_bit_width =
      padded_number_of_inputs * bit_width;

    const auto challenge_z = challenges.V_A_S_rehash;
    const scalarV z_exponents = scalar_exponents
      (challenge_z, padded_number_of_inputs + 3);

    const scalarS z_exponents_skip_2 =
      std::span(z_exponents).subspan(2);

    std::transform
      (
       commits.begin()
       , commits.end()
       , z_exponents_skip_2.begin()
       , std::back_inserter(multiexp_data)
       , [weight_y](const auto& x, const auto& y) -> MultiexpData {
         return {y * weight_y, x};
       }
       );

    const auto challenge_x = challenges.V_A_S_T1_T2;

    multiexp_data.emplace_back(challenge_x * weight_y, proof.T1);
    multiexp_data.emplace_back
      (challenge_x * challenge_x * weight_y, proof.T2);

    multiexp_data.emplace_back(weight_z, proof.A);
    multiexp_data.emplace_back(challenge_x * weight_z, proof.S);

    // Compute the number of rounds for the inner product

    // precalc
    scalarV w_cache(1<<rounds);
    w_cache[0] = winv[0];
    w_cache[1] = challenges.inner_product_challenge_LR[0];
    for (size_t j = 1; j < rounds; ++j)
      {
        const size_t slots = 1<<(j+1);
        for (size_t s = slots; s-- > 0; --s)
          {
            w_cache[s] =
              w_cache[s/2] * challenges.inner_product_challenge_LR[j];
            w_cache[s-1] = w_cache[s/2] * winv[j];
          }
      }

    // Compute the curvepoints from G[i] and H[i]

    const scalarV two_exponents =
      scalar_exponents(rct::s_two, bit_width);

    scalarV z5_v(total_bit_width);
    std::generate
      (
       z5_v.begin()
       , z5_v.end()
       , [
          i = 0
          , yinvpow = s_one
          , ypow = s_one
          , z_exponents_skip_2
          , yinv
          , challenge_y
          , challenge_z
          , weight_z
          , proof
          , w_cache
          , total_bit_width
          , two_exponents
          ] () mutable -> crypto::ec_scalar {
         // Convert the index to binary IN REVERSE
         // and construct the crypto::ec_scalar exponent

         LOG_ERROR_AND_THROW_UNLESS
           (
            i / bit_width < z_exponents_skip_2.size()
            , "invalid z_exponents length "
            );

         LOG_ERROR_AND_THROW_UNLESS
           (
            i % bit_width < two_exponents.size()
            , "invalid two_exponents index"
            );

         const auto zpowTwoN =
           z_exponents_skip_2[ i / bit_width ]
           * two_exponents[ i % bit_width];

         const crypto::ec_scalar h_scalar =
           proof.b * yinvpow * w_cache[(~i) & (total_bit_width-1)]
           - (challenge_z * ypow + zpowTwoN) * yinvpow ;


         yinvpow = yinvpow * yinv;
         ypow = ypow * challenge_y;

         const crypto::ec_scalar r = s_zero - h_scalar * weight_z;
         i++;
         return r;
       }
       );

    scalarV z4_v(total_bit_width);
    std::transform
      (
       w_cache.begin()
       , std::next(w_cache.begin(), total_bit_width)
       , z4_v.begin()
       , [proof, challenge_z, weight_z](const auto& cache) {
         const crypto::ec_scalar g_scalar =
           proof.a * cache + challenge_z;
         return s_zero - g_scalar * weight_z;
       }
       );


    // collect
    const crypto::ec_scalar ip1y =
      sum_of_scalar_exponents(challenge_y, total_bit_width);

    LOG_ERROR_AND_RETURN_UNLESS
      (
       padded_number_of_inputs < z_exponents_skip_2.size()
       , false, "invalid zpow index"
       );

    const auto z_exponents_skip_3 = z_exponents_skip_2.subspan(1);
    const crypto::ec_scalar k1 =
      std::reduce
      (
       z_exponents_skip_3.begin()
       , z_exponents_skip_3.end()
       , s_zero
       );

    const crypto::ec_scalar ip12 =
      std::reduce
      (
       two_exponents.begin()
       , two_exponents.end()
       , crypto::s_0
       );

    const crypto::ec_scalar k =
      s_zero - z_exponents_skip_2.front() * ip1y - k1 * ip12;

    const crypto::ec_scalar y0 = s_zero - proof.tau * weight_y;
    const crypto::ec_scalar y1 =
      (proof.t - (challenge_z * ip1y + k)) * weight_y;

    const crypto::ec_scalar z1 = proof.mu * weight_z;
    const crypto::ec_scalar z3 =
      (proof.t - proof.a * proof.b)
      * challenges.inner_product_challenge
      * weight_z
      ;


    // now check all proofs at once
    multiexp_data.emplace_back(s_one, G_(y0 - z1));
    multiexp_data.emplace_back(z3 - y1, rct::H);

    std::transform
      (
       z4_v.begin()
       , z4_v.end()
       , std::begin(G_V)
       , std::back_inserter(multiexp_data)
       , [](const auto& s, const auto& p) -> MultiexpData
       { return {s, p}; }
       );

    std::transform
      (
       z5_v.begin()
       , z5_v.end()
       , std::begin(H_V)
       , std::back_inserter(multiexp_data)
       , [](const auto& s, const auto& p) -> MultiexpData
       { return {s, p}; }
       );

    if (multiexp(multiexp_data) != crypto::identity)
      {
        LOG_ERROR("Verification failure");
        return false;
      }
    return true;
  }

}
