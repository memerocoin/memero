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

#include "math/ringct/functional/bulletproofs_gen.hpp"
#include "math/ringct/functional/bulletproofs_verify.hpp"

#include "math/crypto/controller/keyGen.hpp"

#include "tools/epee/include/logging.hpp"

#include <atomic>

namespace rct
{
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

    return bulletproof_VERIFY
      (
       commits
       , proof
       , G_V
       , H_V
       );
  }
}
