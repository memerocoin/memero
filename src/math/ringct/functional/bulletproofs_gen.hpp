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
#include "config/lol.hpp"

#include <span>

namespace rct
{
  constexpr size_t bit_width = constant::AMOUNT_BIT_WIDTH;
  constexpr size_t max_outputs = constant::BULLETPROOF_MAX_OUTPUTS;
  constexpr size_t max_vector_length = bit_width * max_outputs;

  crypto::ec_point get_bp_generator_G(const size_t idx);
  crypto::ec_point get_bp_generator_H(const size_t idx);

  pointV get_bp_generator_G_V(const size_t idx);
  pointV get_bp_generator_H_V(const size_t idx);

  struct hash_data_t
  {
    crypto::ec_scalar
    V_A_S
      , V_A_S_rehash
      , V_A_S_T1_T2
      , inner_product_challenge
      ;
    std::vector<crypto::ec_scalar> inner_product_challenge_LR;
  };

  std::optional<hash_data_t> make_hash_challenges
  (const pointS commits, const Bulletproof proof);

  scalarV int_to_bits(const uint64_t x);

  constexpr std::pair<size_t, size_t> ceiling_log2_review(const size_t x) {
    size_t y = 1;
    size_t _log = 0;

    while (y < x) {
      _log++;
      y = y << 1;
    }

    return {y, _log};
  }

  std::optional
  <std::tuple
   <
     crypto::ec_scalar
     , crypto::ec_scalar
     >>
  hash_V_A_S
  (
   const pointS commits
   , const crypto::ec_point x
   , const crypto::ec_point y
   );


  using bp_input_t =
    std::pair<const uint64_t, const crypto::ec_scalar>;

  std::optional
  <std::tuple
   <
     scalarV
     , scalarV
     , crypto::ec_scalar
     , crypto::ec_scalar
     , crypto::ec_point
     , crypto::ec_point
     , crypto::ec_point
     , crypto::ec_point
     , crypto::ec_scalar
     , crypto::ec_scalar
     >>
  get_bp_vectors_for_inner_product_argument
  (
   const std::span<const bp_input_t> xs
   , const crypto::ec_scalar alpha
   , const scalarS sL
   , const scalarS sR
   , const crypto::ec_scalar rho
   , const crypto::ec_scalar tau1
   , const crypto::ec_scalar tau2
   );


}
