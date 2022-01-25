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

  crypto::ec_scalar vector_sum
  (
   const scalarS xs
   ) {
    return std::reduce(xs.begin(), xs.end(), rct::s_zero);
  }

  crypto::ec_point vector_sum
  (
   const pointS xs
   ) {
    return std::reduce(xs.begin(), xs.end(), crypto::identity);
  }

  crypto::ec_scalar sum_of_scalar_exponents
  (
   const crypto::ec_scalar x
   , const size_t n
   )
  {
    return vector_sum(scalar_exponents(x, n));
  }

  rct::scalarV hadamard_product(const scalarS a, const scalarS b)
  {
    LOG_ERROR_AND_THROW_UNLESS
      (
       a.size() <= b.size()
       , "Not enough elements in the second container"
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
       , "Not enough elements in the second container"
       );

    return vector_sum(hadamard_product(a, b));
  }


  rct::scalarV vector_add_V(const scalarS a, const scalarS b)
  {
    LOG_ERROR_AND_THROW_UNLESS
      (
       a.size() <= b.size()
       , "Not enough elements in the second container"
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

  rct::scalarV vector_subtract_V(const scalarS a, const scalarS b)
  {
    LOG_ERROR_AND_THROW_UNLESS
      (
       a.size() <= b.size()
       , "Not enough elements in the second container"
       );

    rct::scalarV res(a.size());
    std::transform
      (
       a.begin()
       , a.end()
       , b.begin()
       , res.begin()
       , [](const auto& x, const auto& y) { return x - y; }
       );

    return res;
  }

  rct::scalarV vector_negate(const scalarS a)
  {
      return vector_subtract_V
      (
       scalar_repeat(s_zero, a.size())
       , a
       );
  }

  rct::pointV vector_add_V(const pointS a, const pointS b)
  {
    LOG_ERROR_AND_THROW_UNLESS
      (
       a.size() <= b.size()
       , "Not enough elements in the second container"
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

  rct::scalarV multiplicative_inverse_V(const rct::scalarV v)
  {
    scalarV r(v.size());

    std::transform
      (
       v.begin()
       , v.end()
       , r.begin()
       , [](const auto& x) { return crypto::multiplicative_inverse(x); }
       );

    return r;
  }


  rct::pointV vector_multP_V(const scalarS a, const pointS p) {
    LOG_ERROR_AND_THROW_UNLESS
      (
       a.size() <= p.size()
       , "Not enough elements in the second container"
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

  std::vector<crypto::ec_point> scalar_multP_V
  (const crypto::ec_scalar a, const pointS p) {
    return vector_multP_V(scalar_repeat(a, p.size()), p);
  }


  crypto::ec_scalar substitute_polynomial
  (const scalarS a, crypto::ec_scalar X) {
    return inner_product
      (
       a
       , scalar_exponents(X, a.size())
       );
  }

  crypto::ec_point vector_commit(const scalarS a, const pointS p) {
    LOG_ERROR_AND_THROW_UNLESS
      (
       a.size() <= p.size()
       , "Not enough elements in the second container"
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

  rct::scalarV scalar_repeat
  (const crypto::ec_scalar x, const size_t n) {
    return vector_mult(scalar_exponents(crypto::s_1, n), x);
  }

  crypto::ec_point homomorphic_hash
  (
   const pointS G
   , const pointS H
   , const scalarS a
   , const scalarS b
   , const crypto::ec_point u
   , const crypto::ec_scalar c
   ) {
    return vector_commit(a, G) + vector_commit(b, H) + (u ^ c);
  }

  crypto::ec_point homomorphic_hash_full
  (
   const pointS G
   , const pointS H
   , const scalarS a_1
   , const scalarS a_2
   , const scalarS b_1
   , const scalarS b_2
   , const crypto::ec_point u
   , const crypto::ec_scalar c
   ) {
    const auto [G_L, G_R] = split_vector(G);
    const auto [H_L, H_R] = split_vector(H);

    return
      vector_commit(a_1, G_L)
      + vector_commit(a_2, G_R)
      + vector_commit(b_1, H_L)
      + vector_commit(b_2, H_R)
      + (u ^ c)
      ;
  }

  scalarV vector_concat(const std::span<const scalarV> xs) {
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

  scalarV span_to_vector(const scalarS xs) {
    return scalarV(xs.begin(), xs.end());
  }

  pointV span_to_vector(const pointS xs) {
    return pointV(xs.begin(), xs.end());
  }

  std::vector<scalarV> vector_mult_V_monadic
  (
   scalarS xs
   , scalarS ys
   )
  {
    std::vector<scalarV> zs;
    std::transform
      (
       xs.begin()
       , xs.end()
       , std::back_inserter(zs)
       , [ys](const auto& x) -> scalarV {
         return vector_mult(ys, x);
       }
       );

    return zs;
  }
} // rct
