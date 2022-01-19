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

#include "accumHash.hpp"

#include "math/ringct/functional/rctOps.hpp"


#include "tools/epee/include/logging.hpp"

#include <mutex>
#include <atomic>
#include <list>
#include <numeric>

namespace rct
{
  std::pair<crypto::ec_scalar, std::vector<crypto::ec_scalar>>
  accum_hash
  (
   const crypto::ec_scalar init_hash
   , const std::vector<std::vector<crypto::crypto_data>> xss
   ) {

    const std::pair<crypto::ec_scalar, std::vector<crypto::ec_scalar>>
      accum_init = {init_hash, {}};

    return std::accumulate
      (
       xss.begin()
       , xss.end()
       , accum_init
       , []
       (
        const auto x
        , const std::vector<crypto::crypto_data> xs
        ) -> std::pair<crypto::ec_scalar, std::vector<crypto::ec_scalar>> {
         std::vector<crypto::crypto_data> ys = xs;
         const crypto::crypto_data last = x.first;

         ys.insert(ys.begin(), last);

         const auto h = hash_dataV_to_scalar(ys);

         std::vector<crypto::ec_scalar> hs = x.second;
         hs.push_back(h);

         return {h, hs};
       }
       );
  }
}
