/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#pragma once

#include "group.hpp"
#include "hash.hpp"

#include <sodium.h>

namespace crypto {

  struct schnorr_signature_unnormalized {
    ec_scalar_unnormalized s;
    ec_scalar_unnormalized scalar_hash;
  };

  struct schnorr_signature {
    ec_scalar s, scalar_hash;

    bool operator==(const schnorr_signature&) const = default;

    bool operator==(const schnorr_signature_unnormalized &x) const noexcept {
      return scalar_hash == x.scalar_hash && s == x.s;
    }

    /*
    bool is_reduced() const noexcept {
      return s == reduce(s) && scalar_hash == reduce(scalar_hash);
    }
    */

  };

  inline schnorr_signature reduce_schnorr(const schnorr_signature_unnormalized x) {
    return {reduce(x.s), reduce(x.scalar_hash)};
  }

  inline std::ostream &operator <<(std::ostream &o, const schnorr_signature &v) {
    epee::hex::append_decode_formatted(o, epee::pod_to_span(v)); return o;
  }

  bool verify_schnorr_signature
  (
   const epee::blob::span message
   , const ec_point_unsafe pub
   , const schnorr_signature sig
   , const std::optional<ec_point_unsafe> base = {}
   );
}
