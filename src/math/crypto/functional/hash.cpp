/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "hash.hpp"

namespace crypto {

hash sha3(const epee::blob::span x) noexcept {
  hash h;
  sha3_raw(x.data(), x.size(), h.data.data());
  return h;
}

hash tree_hash(const std::span<const hash> hashes) noexcept {
  hash root_hash;
  tree_hash(reinterpret_cast<const uint8_t (*)[HASH_SIZE]>(hashes.data()), hashes.size(), root_hash.data.data());
  return root_hash;
}

size_t largest_power_of_two(const size_t x) {
  size_t i = 2;
  while(i < x) {
    i <<= 1;
  }
  return i >> 1;
}

// 5.1 Merkle Root Hash Calculation

// Merkle root hash is computed from the list of transactions as follows: let
// tx[i] be the i-th transaction in the block, where 0 <= i <= n-1 (n is the
// number of transactions) and tx[0] is the base transaction. Let m be the
// largest power of two, less than or equal to n. Define the array h as follows:

// h[i] = H(h[2*i] || h[2*i+1]) where 1 <= i <= m-1 or 3*m-n <= i <= 2*m-1. h[i]
// = H(tx[i-m]) where m <= i <= 3*m-n-1 h[i] = H(tx[i-4*m+n]) where 6*m-2*n <= i
// <= 4*m-1. Where H is the Keccak function that is used throughout CryptoNote,
// and || denotes concatenation. Then, h[1] is the root hash.

// The figure below illustrates the calculation of Merkle root hash in a block
// with 9 transactions. Each arrow represents a computation of H.


hash hash_pair(const hash x, const hash y) {
  return sha3(x.blob() + y.blob());
}

hash hash_at(const std::span<const hash> hashes, const size_t i) {
  const size_t n = hashes.size();
  const size_t m = largest_power_of_two(n);

  // h[i] = H(h[2*i] || h[2*i+1])
  //   where 1 <= i <= m-1 or 3*m-n <= i <= 2*m-1.
  //   h[i] = H(tx[i-m])
  //   where m <= i <= 3*m-n-1
  //   h[i] = H(tx[i-4*m+n])
  //   where 6*m-2*n <= i <= 4*m-1.

  if ( (i > 0 && i < m) || ((i >= 3 * m - n) && (i < 2 * m)) ) {
    return hash_pair(hash_at(hashes, 2 * i), hash_at(hashes, 2 * i + 1));
  } else if ( i >= m && i < 3 * m - n ) {
    return hashes[ i - m ];
  } else if ( (i >= 6 * m - 2 * n) && (i < 4 * m) ) {
    return hashes[ i - 4 * m + n ];
  } else {
    // throw std::runtime_error("invalid case happened in hash-at");
    return null_hash;
  }
}

std::optional<hash> tree_hash_safe(const std::span<const hash> hashes) {
  const size_t n = hashes.size();

  switch (n) {
  case 0: return {};
  case 1: return hashes.front();
  case 2: return hash_pair(hashes.front(), hashes.back());

  default: {
    return hash_at(hashes, 1);
  }

  }
}

hash tree_hash_2(const std::span<const hash> hashes) noexcept {
  const auto r = tree_hash_safe(hashes);
  if (r) {
    return *r;
  } else {
    return null_hash;
  }
}

}


