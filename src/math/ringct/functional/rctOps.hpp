/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#pragma once

#include "rctTypes.hpp"
#include "curveConstants.hpp"

namespace rct {

  // Can't use consteval here or android will panic

  constexpr crypto::ec_scalar s_zero = crypto::s_0;
  constexpr crypto::ec_scalar s_one = crypto::s_1;
  constexpr crypto::ec_scalar s_two = crypto::s_2;
  constexpr crypto::ec_scalar s_minus_one = MINUS_ONE;
  constexpr crypto::ec_scalar s_eight = crypto::s_8;
  // inv is multiplicative inverse
  constexpr crypto::ec_scalar s_inv_eight = INV_EIGHT;
  constexpr crypto::ec_scalar s_minus_inv_eight = MINUS_INV_EIGHT;

  crypto::ec_point G_(const crypto::ec_scalar a);
  crypto::ec_point H_(const crypto::ec_scalar a);

  crypto::ec_point sum(const pointS A);


  // ct
  crypto::ec_point commit(const amount_t amount, const crypto::ec_scalar mask);
  crypto::ec_point dummyCommit(const amount_t amount);

  inv8 to_inv8(const crypto::ec_point x);
  std::optional<crypto::ec_point> maybe_from_inv8(const inv8 x);


  // hash
  crypto::hash hash_data(const crypto::crypto_data in);
  crypto::ec_scalar hash_to_scalar(const crypto::crypto_data in);
  crypto::hash hash_dataV(const std::span<const crypto::crypto_data> keys);
  crypto::ec_scalar hash_dataV_to_scalar(const std::span<const crypto::crypto_data> keys);
  std::optional<crypto::ec_scalar>
  maybe_hash_V_to_non_zero_scalar(const std::span<const crypto::crypto_data> keys);


  // ecdh
  crypto::ec_scalar get_blinding_factor_from_hashed_shared_secret(const crypto::ec_scalar x);
  uint64_t hash_and_xor_int(const uint64_t, const crypto::ec_scalar y);

  inline const auto encode_amount_by_hashed_ecdh_shared_secret = hash_and_xor_int;
  inline const auto decode_amount_by_hashed_ecdh_shared_secret = hash_and_xor_int;
}
