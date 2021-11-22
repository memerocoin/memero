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

using namespace rct;

namespace consensus {

  bool tx_output_amounts_should_not_overflow_amount_type
  (
   const rct_pointS outputs
   , const Bulletproof proof
   );

  bool tx_should_be_balanced
  (
   const rct_pointS inputs
   , const rct_pointS outputs
   , const amount_t fee
   );

  bool tx_input_should_be_from_a_ring
  (
   const crypto::hash message
   , const clsag sig
   , const output_public_dataS decoys
   , const rct_point pseudo_input_commit
   );

  //-----------------------------------------------------------------------------------------------
  consteval uint64_t get_block_reward() {
    return constant::COIN * 300;
  }

  consteval bool block_reward_is_constant_300() {
    return get_block_reward() == constant::COIN * 300;
  }

  static_assert(block_reward_is_constant_300());


}
