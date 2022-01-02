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
  /* Given two crypto::ec_scalar arrays, construct the inner product */
  crypto::ec_scalar inner_product(const scalarS a, const scalarS b);

  /* Given a crypto::ec_scalar, construct a vector of powers */
  rct::scalarV vector_powers(const crypto::ec_scalar x, const size_t n);

  /* Given a crypto::ec_scalar, return the sum of its powers from 0 to n-1 */
  crypto::ec_scalar vector_power_sum(const crypto::ec_scalar x, const size_t n);

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
