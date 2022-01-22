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

#include "rctTypes.hpp"

namespace rct
{
  crypto::ec_scalar inner_product(const scalarS a, const scalarS b);

  rct::scalarV scalar_exponents
  (const crypto::ec_scalar x, const size_t n);

  crypto::ec_scalar sum_of_scalar_exponents
  (
   const crypto::ec_scalar x
   , const size_t n
   );

  rct::scalarV hadamard_product(const scalarS a, const scalarS b);

  rct::scalarV vector_add_V(const scalarS a, const scalarS b);

  rct::pointV vector_add_V(const pointS a, const pointS b);

  rct::scalarV vector_add(const scalarS a, const crypto::ec_scalar b);

  rct::scalarV vector_subtract
  (const scalarS a, const crypto::ec_scalar b);

  rct::scalarV vector_mult
  (const scalarS a, const crypto::ec_scalar b);

  rct::scalarV multiplicative_inverse_V(const rct::scalarV v);

  std::vector<crypto::ec_point> vector_multP_V
  (const scalarS a, const pointS p);

  std::vector<crypto::ec_point> scalar_multP_V
  (const crypto::ec_scalar a, const pointS p);

  crypto::ec_point vector_commit(const scalarS a, const pointS p);

  std::pair<pointV, pointV> split_vector(const pointS v);
  std::pair<scalarV, scalarV> split_vector(const scalarS v);

  rct::scalarV scalar_repeat
  (const crypto::ec_scalar x, const size_t n);

  crypto::ec_point homomorphic_hash
  (
   const pointS vl
   , const pointS vr
   , const scalarS a
   , const scalarS b
   , const crypto::ec_point u
   , const crypto::ec_scalar c
   );

  scalarV vector_concat
  (
   const std::span<scalarV> xs
   );

}
