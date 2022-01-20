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

#include "vectorOps.hpp"
#include "rctOps.hpp"

#include "tools/epee/include/logging.hpp"

#include <numeric>

namespace rct
{

  /* Given a crypto::ec_scalar, construct a vector of powers */
  rct::scalarV vector_exponents(const crypto::ec_scalar x, const size_t n)
  {
    scalarV res(n);

    std::generate(res.begin(), res.end(), [accum = rct::s_one, x] () mutable {
      const auto current = accum;
      accum = accum * x;
      return current;
    });

    return res;
  }

  /* Given a crypto::ec_scalar, return the sum of its powers from 0 to n-1 */
  crypto::ec_scalar sum_of_vector_exponents
  (
   const crypto::ec_scalar x
   , const size_t n
   )
  {
    const auto xs = vector_exponents(x, n);

    return std::reduce(xs.begin(), xs.end(), rct::s_zero);
  }

  /* Given two crypto::ec_scalar arrays, construct the Hadamard product */
  rct::scalarV hadamard_product(const scalarS a, const scalarS b)
  {
    LOG_ERROR_AND_THROW_UNLESS
      (a.size() == b.size(), "Incompatible sizes of a and b");

    rct::scalarV res(a.size());
    std::transform
      (
       a.begin()
       , a.end()
       , b.begin()
       , res.begin()
       , std::multiplies<crypto::ec_scalar>()
       );

    return res;
  }

  /* Given two crypto::ec_scalar arrays, construct the inner product */
  crypto::ec_scalar inner_product(const scalarS a, const scalarS b)
  {
    LOG_ERROR_AND_THROW_UNLESS
      (a.size() == b.size(), "Incompatible sizes of a and b");

    const auto xs = hadamard_product(a, b);
    return std::reduce(xs.begin(), xs.end(), rct::s_zero);
  }


  /* Add two vectors */
  rct::scalarV vector_addV(const scalarS a, const scalarS b)
  {
    LOG_ERROR_AND_THROW_UNLESS
      (a.size() == b.size(), "Incompatible sizes of a and b");

    rct::scalarV res(a.size());
    std::transform
      (
       a.begin()
       , a.end()
       , b.begin()
       , res.begin()
       , std::plus<crypto::ec_scalar>()
       );

    return res;
  }

  /* Add a crypto::ec_scalar to all elements of a vector */
  rct::scalarV vector_add(const scalarS a, const crypto::ec_scalar b)
  {
    rct::scalarV res(a.size());
    std::transform
      (
       a.begin()
       , a.end()
       , res.begin()
       , [b](const auto& x) { return x + b; }
       );

    return res;
  }

  /* Subtract a crypto::ec_scalar from all elements of a vector */
  rct::scalarV vector_subtract(const scalarS a, const crypto::ec_scalar b)
  {
    rct::scalarV res(a.size());
    std::transform
      (
       a.begin()
       , a.end()
       , res.begin()
       , [b](const auto& x) { return x - b; }
       );

    return res;
  }

  /* Multiply a crypto::ec_scalar and a vector */
  rct::scalarV vector_mult(const scalarS a, const crypto::ec_scalar b)
  {
    rct::scalarV res(a.size());
    std::transform
      (
       a.begin()
       , a.end()
       , res.begin()
       , [b](const auto& x) { return x * b; }
       );

    return res;
  }

  rct::scalarV invertV(const rct::scalarV v)
  {
    scalarV r(v.size());

    std::transform
      (
       v.begin()
       , v.end()
       , r.begin()
       , [](const auto& x) { return invert(x); }
       );

    return r;
  }


  crypto::ec_point vector_commit(const scalarS a, const pointS p) {
    LOG_ERROR_AND_THROW_UNLESS
      (a.size() <= p.size(), "Incompatible sizes of a and b");

    return std::transform_reduce
      (
       a.begin()
       , a.end()
       , p.begin()
       , crypto::identity
       , std::plus<crypto::ec_point>()
       , [](const auto& x, const auto& y) { return y ^ x; }
       );
  }

} // rct
