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
  /* Given two crypto::ec_scalar arrays, construct the inner product */
  crypto::ec_scalar inner_product(const scalarS a, const scalarS b);

  /* Given a crypto::ec_scalar, construct a vector of powers */
  rct::scalarV vector_exponents(const crypto::ec_scalar x, const size_t n);

  /* Given a crypto::ec_scalar, return the sum of its powers from 0 to n-1 */
  crypto::ec_scalar sum_of_vector_exponents
  (
   const crypto::ec_scalar x
   , const size_t n
   );

  /* Given two crypto::ec_scalar arrays, construct the Hadamard product */
  rct::scalarV hadamard(const scalarS a, const scalarS b);

  /* Add two vectors */
  rct::scalarV vector_addV(const scalarS a, const scalarS b);

  /* Add a crypto::ec_scalar to all elements of a vector */
  rct::scalarV vector_add(const scalarS a, const crypto::ec_scalar b);

  /* Subtract a crypto::ec_scalar from all elements of a vector */
  rct::scalarV vector_subtract(const scalarS a, const crypto::ec_scalar b);

  /* Multiply a crypto::ec_scalar and a vector */
  rct::scalarV vector_mult(const scalarS a, const crypto::ec_scalar b);

  rct::scalarV invertV(const rct::scalarV v);
}
