// Copyright (c) 2020-2021, The Lolnero Project
// Copyright (c) 2016, Monero Research Labs
//
// Author: Shen Noether <shen.noether@gmx.com>
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
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIomm
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once

#include "rctTypes.hpp"
#include "curveConstants.hpp"

namespace rct {

  //Various key initialization functions

  // Can't us consteval here or android will panic
  // Creates a zero rct_scalar
  constexpr rct_scalar s_zero = ZERO;
  constexpr rct_scalar s_one = ONE;
  constexpr rct_scalar s_two= TWO;
  constexpr rct_scalar s_minus_one = MINUS_ONE;
  constexpr rct_scalar s_eight = EIGHT;
  // inv is multiplicative inverse
  constexpr rct_scalar s_inv_eight = INV_EIGHT;
  constexpr rct_scalar s_minus_inv_eight = MINUS_INV_EIGHT;

  constexpr rct_point zero = Z;

  constexpr rct_point emptyPoint = Z;
  //Creates a zero elliptic curve point
  constexpr rct_point identity = I;

  //initializes a rct_point matrix;
  //first parameter is rows,
  //second is columns
  rct_pointM rct_pointMInit(size_t rows, size_t cols);

  //Various rct_point generation functions

  // make a pedersen commitment with given key
  // generates C = mask * G + amount * H
  rct_point commit(const rct_scalar mask, const amount_t amount);

  // make a pedersen commitment with zero key
  rct_point dummyCommit(const amount_t amount);

  //Scalar multiplications of curve points

  rct_point multG(const rct_scalar a);

  rct_point multP(const rct_point P, const rct_scalar a);

  rct_point multH(const rct_scalar a);

  rct_point multP8(const crypto::ec_point_unsafe P);
  rct_point multP8Safe(const rct_point P);

  //Curve addition / subtractions

  rct::rct_point addPoints(const rct_pointS A);

  rct_point addMultG_H(const rct_scalar a, const rct_scalar b);

  crypto::hash hash_data(const crypto::crypto_data in);
  rct_scalar hash_to_scalar(const crypto::crypto_data in);


  //for mg sigs
  crypto::hash hash_dataV(const std::span<const crypto::crypto_data> keys);
  rct_scalar hash_dataV_to_scalar(const std::span<const crypto::crypto_data> keys);

  //for ANSL

  rct_point hash_to_point_via_field(const crypto::crypto_data k);

  rct_scalar get_blinding_factor_from_ecdh_shared_secret(const rct_scalar x);

  crypto::crypto_data hash_and_xor_first_8_bytes(const crypto::crypto_data x, const rct_scalar y);

  inline const auto encode_by_ecdh_shared_secret = hash_and_xor_first_8_bytes;
  inline const auto decode_by_ecdh_shared_secret = hash_and_xor_first_8_bytes;
}
