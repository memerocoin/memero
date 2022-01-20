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

    const auto maybe_y = accum_hash
      (
       {}
       , {
         commit_data_V
         , { to_inv8(proof.A), to_inv8(proof.S) }
       }
       );

    LOG_ERROR_AND_RETURN_UNLESS
      (maybe_y
       , {}
       , "failed to generate hash challenges"
       );

    const auto y_array = *maybe_y;
    const auto y = y_array.back();
    const auto z = rct::hash_to_scalar(y);
    LOG_ERROR_AND_RETURN_IF((z == rct::s_zero), {}, "z == 0");

    const auto x =
      hash_dataV_to_scalar
      (crypto::dataV{z, z, to_inv8(proof.T1), to_inv8(proof.T2)});

    LOG_ERROR_AND_RETURN_IF((x == rct::s_zero), {}, "x == 0");

    const auto x_ip =
      hash_dataV_to_scalar
      (
       crypto::dataV
       {
         x
         , x
         , proof.taux
         , proof.mu
         , proof.t
       });
    LOG_ERROR_AND_RETURN_IF((x_ip == rct::s_zero), {}, "x_ip == 0");

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

    const auto maybe_w = accum_hash(x_ip, lr_data);
    LOG_ERROR_AND_RETURN_UNLESS(maybe_w, {}, "some w[i] == 0");

    const auto w = *maybe_w;

    return {{
        x
        , y
        , z
        , x_ip
        , w
      }};
  }

}
