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


#include "coinbase_tx.hpp"

#include "tools/epee/include/logging.hpp"

namespace cryptonote {

  std::optional<coinbase_tx> maybe_coinbase_tx(const transaction& tx) {
    LOG_ERROR_AND_RETURN_UNLESS
      (
       tx.version == 2
       , {}
       , "Invalid coinbase transaction version"
       );

    LOG_ERROR_AND_RETURN_UNLESS
      (
       tx.ringct.type == rct::RCTTypeNull
       , {}
       , "Wrong rct type in miner tx"
       );

    return {};
  }

}

