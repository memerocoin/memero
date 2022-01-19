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
