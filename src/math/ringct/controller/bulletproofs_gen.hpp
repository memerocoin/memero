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

#pragma once

#include "math/ringct/functional/rctTypes.hpp"
#include "config/lol.hpp"

#include <span>

namespace rct
{
  constexpr size_t maxN = 64;
  constexpr size_t max_outputs = constant::BULLETPROOF_MAX_OUTPUTS;

  extern std::array<crypto::ec_point, maxN*max_outputs> Hi;
  extern std::array<crypto::ec_point, maxN*max_outputs> Gi;

  constexpr std::pair<size_t, size_t> log2bound(const size_t x) {
    size_t y = 1;
    size_t _log = 0;

    while (y < x) {
      _log++;
      y = y << 1;
    }

    return {y, _log};
  }


  void init_exponents();

  using bp_input_t = std::pair<const uint64_t, const crypto::ec_scalar>;

  Bulletproof bulletproof_MAKE(const std::span<const bp_input_t> xs);
}
