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

#include "cryptonote/basic/functional/base.hpp"

namespace cryptonote {

  struct coinbase_output
  {
    uint64_t amount;
    crypto::public_key output_public_key;
  };
     
  struct coinbase_tx
  {
    uint64_t height;
    std::vector<coinbase_output> outputs;
  };

  std::optional<coinbase_tx> maybe_coinbase_tx(const transaction& tx);

}
