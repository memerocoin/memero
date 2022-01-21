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

  rct::scalarV scalar_exponents
  (const crypto::ec_scalar x, const size_t n)
  {
    scalarV res(n);

    std::generate
      (
       res.begin()
       , res.end()
       , [accum = rct::s_one, x] () mutable
       {
         const auto current = accum;
         accum = accum * x;
         return current;
       });

    return res;
  }

  crypto::ec_scalar sum_of_scalar_exponents
  (
   const crypto::ec_scalar x
   , const size_t n
   )
  {
    const auto xs = scalar_exponents(x, n);

    return std::reduce(xs.begin(), xs.end(), rct::s_zero);
  }

  rct::scalarV hadamard_product(const scalarS a, const scalarS b)
  {
    LOG_ERROR_AND_THROW_UNLESS
      (
       a.size() <= b.size()
       , "Size of the first vector is bigger than the second"
       );

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

  crypto::ec_scalar inner_product(const scalarS a, const scalarS b)
  {
    LOG_ERROR_AND_THROW_UNLESS
      (
       a.size() <= b.size()
       , "Size of the first vector is bigger than the second"
       );

    const auto xs = hadamard_product(a, b);
    return std::reduce(xs.begin(), xs.end(), rct::s_zero);
  }


  rct::scalarV vector_addV(const scalarS a, const scalarS b)
  {
    LOG_ERROR_AND_THROW_UNLESS
      (
       a.size() <= b.size()
       , "Size of the first vector is bigger than the second"
       );

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

  rct::pointV vector_addV(const pointS a, const pointS b)
  {
    LOG_ERROR_AND_THROW_UNLESS
      (
       a.size() <= b.size()
       , "Size of the first vector is bigger than the second"
       );

    rct::pointV res(a.size());
    std::transform
      (
       a.begin()
       , a.end()
       , b.begin()
       , res.begin()
       , std::plus<crypto::ec_point>()
       );

    return res;
  }

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

  rct::scalarV vector_subtract
  (const scalarS a, const crypto::ec_scalar b)
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


  rct::pointV vector_multP_V(const scalarS a, const pointS p) {
    LOG_ERROR_AND_THROW_UNLESS
      (
       a.size() <= p.size()
       , "Size of the first vector is bigger than the second"
       );

    pointV r(a.size());

    std::transform
      (
       a.begin()
       , a.end()
       , p.begin()
       , r.begin()
       , [](const auto& x, const auto& y) { return y ^ x; }
       );

    return r;
  }

  crypto::ec_point vector_commit(const scalarS a, const pointS p) {
    LOG_ERROR_AND_THROW_UNLESS
      (
       a.size() <= p.size()
       , "Size of the first vector is bigger than the second"
       );

    const auto xs = vector_multP_V(a, p);
    return std::reduce(xs.begin(), xs.end(), crypto::identity);
  }

  std::pair<pointV, pointV> split_vector(const pointS v) {
    LOG_ERROR_AND_THROW_IF(v.empty(), "Vector can't be empty");
    LOG_ERROR_AND_THROW_UNLESS
      ((v.size() & 1) == 0, "Vector size should be even");

    const size_t middle = v.size() / 2;
    return
      {
        pointV(v.begin(), std::next(v.begin(), middle))
        , pointV(std::next(v.begin(), middle), v.end())
      };
  }

  std::pair<scalarV, scalarV> split_vector(const scalarS v) {
    LOG_ERROR_AND_THROW_IF(v.empty(), "Vector can't be empty");
    LOG_ERROR_AND_THROW_UNLESS
      ((v.size() & 1) == 0, "Vector size should be even");

    const size_t middle = v.size() / 2;
    return
      {
        scalarV(v.begin(), std::next(v.begin(), middle))
        , scalarV(std::next(v.begin(), middle), v.end())
      };
  }

  rct::scalarV vector_repeat
  (const crypto::ec_scalar x, const size_t n) {
    return vector_mult(scalar_exponents(crypto::s_1, n), x);
  }

  crypto::ec_point homomorphic_hash
  (
   const pointS vl
   , const pointS vr
   , const scalarS a
   , const scalarS b
   , const crypto::ec_point u
   , const crypto::ec_scalar c
   ) {
    return vector_commit(a, vl) + vector_commit(b, vr) + (u ^ c);
  }

  pointV vector_multP_add
  (
   const scalarS a
   , const scalarS b
   , const pointS vl
   , const pointS vr
   )
  {
    LOG_ERROR_AND_THROW_UNLESS
      (vl.size() == vr.size(), "Vector size should be even");

    const pointV l = vector_multP_V(a, vl);
    const pointV r = vector_multP_V(b, vr);

    return vector_addV(l, r);
  }

  scalarV vector_concat(const std::span<scalarV> xs) {
    return std::reduce
      (
       xs.begin()
       , xs.end()
       , scalarV()
       , [](const auto x, const auto y) -> scalarV {
         scalarV z(x.begin(), x.end());
         z.insert(z.end(), y.begin(), y.end());
         return z;
       }
       );
  }

} // rct
