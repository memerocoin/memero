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

#include <span>

namespace rct
{

  struct proof_data_t
  {
    crypto::ec_scalar
        V_A_S_T1_T2
        , V_A_S
        , V_A_S_rehash
        , inner_product_challenge
      ;
    std::vector<crypto::ec_scalar> inner_product_challenge_LR;
  };

  std::optional<proof_data_t> make_hash_challenges
  (const pointS commits, const Bulletproof proof);

  scalarV int_to_bits(const uint64_t x);

  constexpr std::pair<size_t, size_t> log2bound(const size_t x) {
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
    const pointS V
    , const scalarS blinding_factors
    , const size_t padded_number_of_inputs
    , const size_t bit_width
    , const size_t total_bit_width
    , const scalarS aL
    , const scalarS aR
    , const crypto::ec_scalar alpha
    , const scalarS sL
    , const scalarS sR
    , const crypto::ec_scalar rho
    , const crypto::ec_scalar tau1
    , const crypto::ec_scalar tau2
    , const pointS G_V
    , const pointS H_V
   );


}
