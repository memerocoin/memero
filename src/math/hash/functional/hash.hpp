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

#include "math/hash/pseudo_functional/sha3.hpp"

#include "tools/epee/functional/hex.hpp"

#include <boost/functional/hash.hpp>

#include <cstddef>

constexpr size_t HASH_SIZE = 32;

namespace crypto {

  struct hash {
    std::array<uint8_t, HASH_SIZE> data;
    bool operator==(const hash&) const = default;

    inline epee::blob::data blob() const {
      return epee::blob::data(data.begin(), data.end());
    }

    inline std::string to_str() const {
      return epee::hex::encode_to_hex_formatted(data);
    }
  };

  inline std::ostream &operator <<(std::ostream &o, const crypto::hash &v) {
    o << epee::hex::encode_to_hex_formatted(v.data);
    return o;
  }

  struct hash8 {
    std::array<uint8_t, 8> data;
  };
  inline std::ostream &operator <<(std::ostream &o, const crypto::hash8 &v) {
    o << epee::hex::encode_to_hex_formatted(v.data);
    return o;
  }

  constexpr crypto::hash null_hash = {};
  constexpr crypto::hash8 null_hash8 = {};

  hash sha3(const epee::blob::span) noexcept;
}

namespace std
{
  template<> struct hash<crypto::hash>
  {
    std::size_t operator()(crypto::hash const& x) const noexcept
    {
      boost::hash<std::array<uint8_t, HASH_SIZE>> array_hash;
      return array_hash(x.data);
    }
  };
}
