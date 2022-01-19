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
  struct hash_input_t
  {
    pointV commits;
    crypto::ec_point A, S;
    crypto::ec_point T1, T2;
    crypto::ec_scalar taux, mu;
    crypto::ec_scalar a, b, t;
  };

  std::optional<proof_data_t> make_hash_challenges
  (const pointS commits, const Bulletproof proof) {
    // hash_input_t hash_input;
    // hash_input.commits = commits;

    crypto::dataV hash_dataV;
    std::transform
      (
       commits.begin()
       , commits.end()
       , std::back_inserter(hash_dataV)
       , to_inv8
       );

    crypto::ec_scalar hash_carry = rct::hash_dataV_to_scalar(hash_dataV);

    proof_data_t pd;
    pd.y = hash_carry = hash_dataV_to_scalar
      (crypto::dataV{hash_carry, to_inv8(proof.A), to_inv8(proof.S)});
    LOG_ERROR_AND_RETURN_IF((pd.y == rct::s_zero), {}, "y == 0");

    pd.z = hash_carry = rct::hash_to_scalar(pd.y);
    LOG_ERROR_AND_RETURN_IF((pd.z == rct::s_zero), {}, "z == 0");

    pd.x = hash_carry =
      hash_dataV_to_scalar
      (crypto::dataV{hash_carry, pd.z, to_inv8(proof.T1), to_inv8(proof.T2)});
    LOG_ERROR_AND_RETURN_IF((pd.x == rct::s_zero), {}, "x == 0");

    pd.x_ip = hash_carry =
      hash_dataV_to_scalar
      (
       crypto::dataV
       {
         hash_carry
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

    const auto maybe_pd_w = accum_hash(hash_carry, {lr_data});
    LOG_ERROR_AND_RETURN_UNLESS(maybe_pd_w, {}, "some pd_w[i] == 0");

    pd.w = *maybe_pd_w;

    return pd;
  }

}
