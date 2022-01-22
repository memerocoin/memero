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

#pragma once

#include "math/ringct/functional/rctTypes.hpp"
#include "math/ringct/functional/bulletproofs.hpp"
#include "config/lol.hpp"

#include <span>

namespace rct
{
  extern std::array<crypto::ec_point, max_vector_length> H_V;
  extern std::array<crypto::ec_point, max_vector_length> G_V;

  void init_generators();
  crypto::ec_point get_generator_G(const size_t idx);
  crypto::ec_point get_generator_H(const size_t idx);

  Bulletproof bulletproof_MAKE(const std::span<const bp_input_t> xs);
}
