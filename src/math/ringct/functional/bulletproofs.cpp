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
#include "math/ringct/functional/curveConstants.hpp"
#include "math/ringct/functional/multi_exponentiation.hpp"

#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/string_tools.h"

#include "config/cryptonote.hpp"

#include <mutex>
#include <atomic>
#include <list>
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

    proof_data_t pd;
    const auto maybe_pd_y = accum_hash
      (
       {}
       , {
         commit_data_V
         , { to_inv8(proof.A), to_inv8(proof.S) }
       }
       );

    LOG_ERROR_AND_RETURN_UNLESS
      (maybe_pd_y
       , {}
       , "failed to generate hash challenges"
       );

    const auto pd_y_array = *maybe_pd_y;
    pd.y = pd_y_array.back();
    pd.z = rct::hash_to_scalar(pd.y);
    LOG_ERROR_AND_RETURN_IF((pd.z == rct::s_zero), {}, "z == 0");

    pd.x =
      hash_dataV_to_scalar
      (crypto::dataV{pd.z, pd.z, to_inv8(proof.T1), to_inv8(proof.T2)});

    LOG_ERROR_AND_RETURN_IF((pd.x == rct::s_zero), {}, "x == 0");

    pd.x_ip =
      hash_dataV_to_scalar
      (
       crypto::dataV
       {
         pd.x
         , pd.x
         , proof.taux
         , proof.mu
         , proof.t
       });
    LOG_ERROR_AND_RETURN_IF((pd.x_ip == rct::s_zero), {}, "x_ip == 0");

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

    const auto maybe_pd_w = accum_hash(pd.x_ip, {lr_data});
    LOG_ERROR_AND_RETURN_UNLESS(maybe_pd_w, {}, "some pd_w[i] == 0");

    pd.w = *maybe_pd_w;

    return pd;
  }

}
