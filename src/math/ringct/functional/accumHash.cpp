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
  using accumState =
    std::optional
    <
    std::pair
    <
      crypto::ec_scalar
      , rct::scalarV
      >>;

  std::optional<rct::scalarV> accum_hash
  (
   const crypto::ec_scalar init_hash
   , const std::vector<crypto::dataV> xss
   ) {
    if (xss.empty()) {
      return {};
    }

    const accumState accum_init = {{init_hash, {}}};
    const auto hash_pair = std::accumulate
      (
       xss.begin()
       , xss.end()
       , accum_init
       , []
       (
        const auto x
        , const crypto::dataV xs
        ) -> accumState
       {

         if (!x) {
           return {};
         }

         const crypto::crypto_data last = x->first;

         crypto::dataV ys = xs;

         ys.insert(ys.begin(), last);

         const auto maybe_h = maybe_hash_V_to_non_zero_scalar(ys);
         if (!maybe_h) {
           return {};
         }
         const auto h = *maybe_h;

         rct::scalarV hs = x->second;
         hs.push_back(h);

         return {{h, hs}};
       }
       );

    if (!hash_pair) {
      return {};
    } else {
      return hash_pair->second;
    }
  }
}
