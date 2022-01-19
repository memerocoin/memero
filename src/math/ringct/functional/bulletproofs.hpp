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

#include <span>

namespace rct
{

  struct proof_data_t
  {
    crypto::ec_scalar x, y, z, x_ip;
    std::vector<crypto::ec_scalar> w;
  };

  std::optional<proof_data_t> make_hash_challenges
  (const pointS commits, const Bulletproof proof);

}
