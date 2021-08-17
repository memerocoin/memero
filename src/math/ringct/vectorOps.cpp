// Copyright (c) 2021, The Lolnero Project
// Copyright (c) 2017-2020, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Adapted from Java code by Sarang Noether
// Paper references are to https://eprint.iacr.org/2017/1066 (revision 1 July 2018)

#include "vectorOps.hpp"
#include "rctOps.hpp"

#include "tools/epee/include/logging.hpp"

#include <list>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "vectorOps"

namespace rct
{

  /* Given two rct_scalar arrays, construct the inner product */
  rct::rct_scalar inner_product(const rct_scalarS a, const rct_scalarS b)
  {
    LOG_ERROR_AND_THROW_UNLESS(a.size() == b.size(), "Incompatible sizes of a and b");
    return std::transform_reduce
      (
       a.begin()
       , a.end()
       , b.begin()
       , rct::s_zero
       , std::plus<rct_scalar>()
       , std::multiplies<rct_scalar>()
       );
  }

  /* Given a rct_scalar, construct a vector of powers */
  rct::rct_scalarV vector_powers(const rct::rct_scalar x, const size_t n)
  {
    rct_scalarV res(n);

    std::generate(res.begin(), res.end(), [accum = rct::s_one, x] () mutable {
      const auto current = accum;
      accum = accum * x;
      return current;
    });

    return res;
  }

  /* Given a rct_scalar, return the sum of its powers from 0 to n-1 */
  rct::rct_scalar vector_power_sum(const rct::rct_scalar x, const size_t n)
  {
    const auto xs = vector_powers(x, n);

    return std::reduce(xs.begin(), xs.end(), rct::s_zero);
  }

  /* Given two rct_scalar arrays, construct the Hadamard product */
  rct::rct_scalarV hadamard(const rct_scalarS a, const rct_scalarS b)
  {
    LOG_ERROR_AND_THROW_UNLESS(a.size() == b.size(), "Incompatible sizes of a and b");
    rct::rct_scalarV res(a.size());
    std::transform
      (
       a.begin()
       , a.end()
       , b.begin()
       , res.begin()
       , std::multiplies<rct_scalar>()
       );

    return res;
  }

  /* Add two vectors */
  rct::rct_scalarV vector_addV(const rct_scalarS a, const rct_scalarS b)
  {
    LOG_ERROR_AND_THROW_UNLESS(a.size() == b.size(), "Incompatible sizes of a and b");
    rct::rct_scalarV res(a.size());
    std::transform
      (
      a.begin()
      , a.end()
      , b.begin()
      , res.begin()
      , std::plus<rct_scalar>()
      );

    return res;
  }

  /* Add a rct_scalar to all elements of a vector */
  rct::rct_scalarV vector_add(const rct_scalarS a, const rct::rct_scalar b)
  {
    rct::rct_scalarV res(a.size());
    std::transform
      (
      a.begin()
      , a.end()
      , res.begin()
      , [b](const auto& x) { return x + b; }
      );

    return res;
  }

  /* Subtract a rct_scalar from all elements of a vector */
  rct::rct_scalarV vector_subtract(const rct_scalarS a, const rct::rct_scalar b)
  {
    rct::rct_scalarV res(a.size());
    std::transform
      (
      a.begin()
      , a.end()
      , res.begin()
      , [b](const auto& x) { return x - b; }
      );

    return res;
  }

  /* Multiply a rct_scalar and a vector */
  rct::rct_scalarV vector_mult(const rct_scalarS a, const rct::rct_scalar b)
  {
    rct::rct_scalarV res(a.size());
    std::transform
      (
      a.begin()
      , a.end()
      , res.begin()
      , [b](const auto& x) { return x * b; }
      );

    return res;
  }

  /* Compute the inverse of a rct_scalar, the clever way */
  rct::rct_scalar invert(const rct::rct_scalar x)
  {
    return s2s(crypto::invert(x));
  }

  rct::rct_scalarV invertV(const rct::rct_scalarV v)
  {
    rct_scalarV r(v.size());

    std::transform
      (
      v.begin()
      , v.end()
      , r.begin()
      , [](const auto& x) { return invert(x); }
      );

    return r;
  }

} // rct
