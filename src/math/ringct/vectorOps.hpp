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


#pragma once

#include "rctTypes.hpp"

namespace rct
{
  /* Given two rct_scalar arrays, construct the inner product */
  rct::rct_scalar inner_product(const rct_scalarS a, const rct_scalarS b);
  /* Given a rct_scalar, construct a vector of powers */
  rct::rct_scalarV vector_powers(const rct::rct_scalar x, const size_t n);
  /* Given a rct_scalar, return the sum of its powers from 0 to n-1 */
  rct::rct_scalar vector_power_sum(const rct::rct_scalar x, const size_t n);
  /* Given two rct_scalar arrays, construct the Hadamard product */
  rct::rct_scalarV hadamard(const rct_scalarS a, const rct_scalarS b);
  /* Add two vectors */
  rct::rct_scalarV vector_addV(const rct_scalarS a, const rct_scalarS b);
  /* Add a rct_scalar to all elements of a vector */
  rct::rct_scalarV vector_add(const rct_scalarS a, const rct::rct_scalar b);
  /* Subtract a rct_scalar from all elements of a vector */
  rct::rct_scalarV vector_subtract(const rct_scalarS a, const rct::rct_scalar b);
  /* Multiply a rct_scalar and a vector */
  rct::rct_scalarV vector_mult(const rct_scalarS a, const rct::rct_scalar b);
  /* Compute the inverse of a rct_scalar, the clever way */
  rct::rct_scalar invert(const rct::rct_scalar x);

  rct::rct_scalarV invertV(const rct::rct_scalarV v);
}
