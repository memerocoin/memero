/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "group.hpp"

#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/int-util.h"


#include <sodium.h>

#include <cassert>
#include <mutex>
#include <memory>


extern "C" {
#include "crypto-ops.h"
}


namespace crypto {

  ec_point add(const ec_point X, const ec_point Y) noexcept {
    ec_point p;
    int r = crypto_core_ed25519_add(p.data.data(), X.data.data(), Y.data.data());
    if (r != 0) {
      LOG_FATAL("add keys not in main group: " << X << "\n" << Y);
    }

    return p;
  }

  ec_point ec_point::operator+(const ec_point& x) const noexcept {
    return add(*this, x);
  }

  ec_point sub(const ec_point X, const ec_point Y) noexcept {
    ec_point p;
    int r = crypto_core_ed25519_sub(p.data.data(), X.data.data(), Y.data.data());
    if (r != 0) {
      LOG_FATAL("sub keys not in main group: " << X << "\n" << Y);
    }

    return p;
  }

  ec_point ec_point::operator-(const ec_point& x) const noexcept {
    return sub(*this, x);
  }


  ec_point mult(const ec_scalar a, const ec_point X) noexcept {
    if (a == s_0) {
      return identity;
    }

    ec_point x;
    const int r = crypto_scalarmult_ed25519_noclamp(x.data.data(), a.data.data(), X.data.data());
    if (r != 0) {
      LOG_FATAL
        (
         "mult point is not on curve: \npoint: " << X
         // << "\nscalar" << a
         << "\nresult: " << x);
    }

    return x;
  }

  ec_point ec_point::operator^(const ec_scalar& x) const noexcept {
    return mult(x, *this);
  }

  ec_point ec_point::operator^(const uint64_t x) const noexcept {
    return mult(int_to_scalar(x), *this);
  }

  ec_scalar ec_scalar::operator+(const ec_scalar& x) const noexcept {
    ec_scalar s;
    crypto_core_ed25519_scalar_add(s.data.data(), this->data.data(), x.data.data());
    return s;
  }

  ec_scalar ec_scalar::operator-(const ec_scalar& x) const noexcept {
    ec_scalar s;
    crypto_core_ed25519_scalar_sub(s.data.data(), this->data.data(), x.data.data());
    return s;
  }

  ec_scalar ec_scalar::operator*(const ec_scalar& x) const noexcept {
    ec_scalar s;
    crypto_core_ed25519_scalar_mul(s.data.data(), this->data.data(), x.data.data());
    return s;
  }

  bool is_safe_point(const ec_point_unsafe x) noexcept {
    return crypto_core_ed25519_is_valid_point(x.data.data());
  }

  bool is_valid_group_element(const ec_point_unsafe x) noexcept {
    // here identity really means zero_small_order
    return x == identity || is_safe_point(x);
  }


  ec_point multBase(const ec_scalar x) noexcept {
    ec_point p;
    const int r = crypto_scalarmult_ed25519_base_noclamp(p.data.data(), x.data.data());
    if (r != 0) {
      LOG_FATAL("scalar mult base failed");
    }
    return p;
  }

  ec_point mult8(const ec_point X) noexcept {
    return mult(s_8, X);
  }

  // multiplicative inverse
  ec_scalar invert(const ec_scalar x) noexcept
  {
    ec_scalar r;
    crypto_core_ed25519_scalar_invert(r.data.data(), x.data.data());
    return r;
  }

  ec_scalar reduce(const ec_scalar_unnormalized x) noexcept {
    unsigned char t[64] = {0};
    std::copy(x.data.begin(), x.data.end(), t);

    ec_scalar s;
    crypto_core_ed25519_scalar_reduce(s.data.data(), t);
    return s;
  }

  bool is_reduced(const ec_scalar_unnormalized x) noexcept {
    return reduce(x) == x;
  }

  bool is_not_reduced(const ec_scalar_unnormalized x) noexcept {
    return !(is_reduced(x));
  }

  std::optional<ec_point> maybeSafePoint(const ec_point_unsafe x) noexcept {
    if (is_safe_point(x)) {
      return unsafe_p2p(x);
    } else {
      return {};
    }
  }

  ec_scalar int_to_scalar(const uint64_t in) noexcept {
    ec_scalar x = {};
    memcpy_swap64le(x.data.data(), &in, 1);
    return x;
  }

  uint64_t scalar_to_int(const ec_scalar & in) noexcept {
    uint64_t out = 0;
    memcpy_swap64le(&out, in.data.data(), 1);
    return out;
  }

}
