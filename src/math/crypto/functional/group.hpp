/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#pragma once

#include "tools/epee/include/hex.h"
#include "tools/epee/include/blob.hpp"

#include <sodium.h>

#include <array>

namespace crypto {
  struct crypto_data {
    std::array<uint8_t, 32> data;

    inline epee::blob::data blob() const {
      return epee::blob::data(data.begin(), data.end());
    }
  };

  // not really functional but needed in other part of the code
  inline std::ostream &operator <<(std::ostream &o, const crypto::crypto_data &v) {
    epee::hex::append_decode_formatted(o, v.data); return o;
  }

  using dataV = std::vector<crypto_data>;
  using dataS = std::span<crypto_data>;


  struct ec_point_unsafe : crypto_data {
    bool operator==(const ec_point_unsafe &x) const noexcept {
      return 0 == crypto_verify_32(data.data(), x.data.data());
    }
  };

  struct ec_point_unsafe_small_order : ec_point_unsafe {};

  struct ec_scalar; // for ^
  struct ec_point : ec_point_unsafe {
    ec_point operator+(const ec_point& x) const noexcept;
    ec_point operator-(const ec_point& x) const noexcept;
    ec_point operator^(const ec_scalar& x) const noexcept;
  };

  struct ec_scalar_unnormalized : crypto_data {
    bool operator==(const ec_scalar_unnormalized &x) const noexcept {
      return 0 == crypto_verify_32(data.data(), x.data.data());
    }
  };

  struct ec_scalar : ec_scalar_unnormalized {
    ec_scalar operator+(const ec_scalar& x) const noexcept;
    ec_scalar operator-(const ec_scalar& x) const noexcept;
    ec_scalar operator*(const ec_scalar& x) const noexcept;
  };


  inline constexpr ec_scalar s_0 = {};
  inline constexpr ec_scalar s_1 =
    {{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
  inline constexpr ec_scalar s_8 =
    {{ 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

  inline const ec_scalar order_minus_1 = s_0 - s_1;

  inline constexpr ec_point_unsafe_small_order zero_small_order =
    {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

  inline constexpr ec_point_unsafe_small_order one_small_order =
    {{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

  // pretty arbitrarily defined in libsodium
  inline constexpr ec_point identity =
    {{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

  inline constexpr ec_point generator =
    { { 0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
        , 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 } };

  inline const ec_point &unsafe_p2p(const ec_point_unsafe &x) noexcept {
    return (const ec_point&)x;
  }


  bool is_not_identity_but_valid(const ec_point_unsafe x) noexcept;
  bool is_valid_group_element(const ec_point_unsafe x) noexcept;

  std::optional<ec_point> maybeSafePoint(const ec_point_unsafe x) noexcept;
  ec_point mult8Safe(const ec_point X) noexcept;
  ec_point multBase(const ec_scalar) noexcept;

  ec_scalar invert(const ec_scalar x) noexcept;

  ec_scalar reduce(const ec_scalar_unnormalized x) noexcept;
  bool is_reduced(const ec_scalar_unnormalized x) noexcept;
  bool is_not_reduced(const ec_scalar_unnormalized x) noexcept;

}
