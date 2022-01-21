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


// Copyright (c) 2021, The Lolnero Project
// Copyright (c) 2017-2020, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Adapted from Java code by Sarang Noether
// Paper references are to https://eprint.iacr.org/2017/1066 (revision 1 July 2018)

#include "bulletproofs.hpp"

#include "math/ringct/functional/vectorOps.hpp"
#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/functional/accumHash.hpp"
#include "math/ringct/functional/bulletproofs.hpp"
#include "math/ringct/functional/curveConstants.hpp"
#include "math/ringct/functional/multi_exponentiation.hpp"
#include "math/ringct/controller/bulletproofs_gen.hpp"

#include "math/crypto/controller/keyGen.hpp"

#include "tools/epee/include/logging.hpp"

#include <atomic>

namespace rct
{

  const scalarV oneN = vector_exponents(rct::s_one, bit_width);
  const scalarV twoN = vector_exponents(rct::s_two, bit_width);

  const crypto::ec_scalar ip12 = inner_product(oneN, twoN);

  const auto multiexp = dummy;

  /* G_Vven a range proof, determine if it is valid
   * This uses the method in PAPER LINES 95-105,
   *   weighted across multiple proofs in a batch
   */
  bool bulletproof_VERIFY(const pointS commits, const Bulletproof proof)
  {
    init_generators();

    // sanity and figure out which proof is longest
    // STEP 1, fill proof_data

    LOG_ERROR_AND_RETURN_UNLESS
      (
       commits.size() >= 1
       , false
       , "commits V does not have at least one element"
       );

    LOG_ERROR_AND_RETURN_UNLESS(proof.LR.size() > 0, false, "Empty proof");
    LOG_ERROR_AND_RETURN_UNLESS
      (commits.size() <= max_outputs, false, "too many points for the proof");

    constexpr size_t logN = log2bound(bit_width).second;
    const auto [padded_number_of_inputs, log_padded_number_of_inputs] =
      log2bound(commits.size());

    const size_t rounds = log_padded_number_of_inputs + logN;
    LOG_ERROR_AND_RETURN_UNLESS
      (proof.LR.size() == rounds, false, "Proof is not the expected size");


    // Reconstruct the challenges

    const auto maybe_pd = make_hash_challenges(commits, proof);

    LOG_ERROR_AND_RETURN_UNLESS
      (maybe_pd, false, "invalid hash challenges");

    const proof_data_t pd = *maybe_pd;

    // STEP 2, use proof_data
    std::vector<MultiexpData> multiexp_data;

    // setup weighted aggregates

    const scalarV winv = invertV(pd.w);
    const crypto::ec_scalar yinv = invert(pd.y);

    const crypto::ec_scalar weight_y = crypto::randomScalar();
    const crypto::ec_scalar weight_z = crypto::randomScalar();

    std::transform
      (
       pd.w.begin()
       , pd.w.end()
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

    const size_t MN = padded_number_of_inputs * bit_width;

    const scalarV zpow = vector_exponents(pd.z, padded_number_of_inputs + 3);

    std::transform
      (
       commits.begin()
       , commits.end()
       , std::next(std::next(zpow.begin()))
       , std::back_inserter(multiexp_data)
       , [weight_y](const auto& x, const auto& y) -> MultiexpData {
         return {y * weight_y, x};
       }
       );

    multiexp_data.emplace_back(pd.x * weight_y, proof.T1);
    multiexp_data.emplace_back(pd.x * pd.x * weight_y, proof.T2);
    multiexp_data.emplace_back(weight_z, proof.A);
    multiexp_data.emplace_back(pd.x * weight_z, proof.S);

    // Compute the number of rounds for the inner product

    // precalc
    scalarV w_cache(1<<rounds);
    w_cache[0] = winv[0];
    w_cache[1] = pd.w[0];
    for (size_t j = 1; j < rounds; ++j)
      {
        const size_t slots = 1<<(j+1);
        for (size_t s = slots; s-- > 0; --s)
          {
            w_cache[s] = w_cache[s/2] * pd.w[j];
            w_cache[s-1] = w_cache[s/2] * winv[j];
          }
      }

    // Compute the curvepoints from G[i] and H[i]
    scalarV z5_v(MN);
    std::generate
      (
       z5_v.begin()
       , z5_v.end()
       , [i = 0, yinvpow = s_one, ypow = s_one
          , zpow, yinv, pd, weight_z, proof, w_cache, MN
          ] () mutable -> crypto::ec_scalar {
         // Convert the index to binary IN REVERSE and construct the crypto::ec_scalar exponent

         LOG_ERROR_AND_THROW_UNLESS
           (2 + i / bit_width < zpow.size(), "invalid zpow index");

         LOG_ERROR_AND_THROW_UNLESS
           (i % bit_width < twoN.size(), "invalid twoN index");

         const auto zpowTwoN = zpow[ 2 + i / bit_width] * twoN[ i % bit_width];

         const crypto::ec_scalar h_scalar =
           proof.b * yinvpow * w_cache[(~i) & (MN-1)]
           - (pd.z * ypow + zpowTwoN) * yinvpow ;


         yinvpow = yinvpow * yinv;
         ypow = ypow * pd.y;

         const crypto::ec_scalar r = s_zero - h_scalar * weight_z;
         i++;
         return r;
       }
       );

    scalarV z4_v(MN);
    std::transform
      (
       w_cache.begin()
       , std::next(w_cache.begin(), MN)
       , z4_v.begin()
       , [proof, pd, weight_z](const auto& cache) {
         const crypto::ec_scalar g_scalar = proof.a * cache + pd.z;
         return s_zero - g_scalar * weight_z;
       }
       );


    // collect
    const crypto::ec_scalar ip1y = sum_of_vector_exponents(pd.y, MN);
    LOG_ERROR_AND_RETURN_UNLESS
      (padded_number_of_inputs + 2 < zpow.size(), false, "invalid zpow index");

    const auto zpow_it = std::next(zpow.begin(), 3);
    const crypto::ec_scalar k1 =
      std::reduce
      (
       zpow_it
       , std::next(zpow_it, padded_number_of_inputs)
       , s_zero
       );

    const crypto::ec_scalar k = s_zero - zpow[2] * ip1y - k1 * ip12;

    const crypto::ec_scalar y0 = s_zero - proof.taux * weight_y;
    const crypto::ec_scalar y1 = (proof.t - (pd.z * ip1y + k)) * weight_y;
    const crypto::ec_scalar z1 = proof.mu * weight_z;
    const crypto::ec_scalar z3 = (proof.t - proof.a * proof.b) * pd.x_ip * weight_z;


    // now check all proofs at once
    multiexp_data.emplace_back(s_one, G_(y0 - z1));
    multiexp_data.emplace_back(z3 - y1, rct::H);

    std::transform
      (
       z4_v.begin()
       , z4_v.end()
       , std::begin(G_V)
       , std::back_inserter(multiexp_data)
       , [](const auto& s, const auto& p) -> MultiexpData { return {s, p}; }
       );

    std::transform
      (
       z5_v.begin()
       , z5_v.end()
       , std::begin(H_V)
       , std::back_inserter(multiexp_data)
       , [](const auto& s, const auto& p) -> MultiexpData { return {s, p}; }
       );

    if (multiexp(multiexp_data) != crypto::identity)
      {
        LOG_ERROR("Verification failure");
        return false;
      }
    return true;
  }

}
