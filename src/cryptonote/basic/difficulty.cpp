// Copyright (c) 2021, The Lolnero Project
// Copyright (c) 2014-2020, The Monero Project
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
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "difficulty.h"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "tools/epee/include/int-util.h"
#include "math/crypto/hash.hpp"
#include "config/cryptonote.hpp"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "difficulty"

namespace cryptonote {

  using std::size_t;
  using std::uint64_t;
  using std::vector;

  static inline void mul(uint64_t a, uint64_t b, uint64_t &low, uint64_t &high) {
    low = mul128(a, b, &high);
  }

  static inline bool cadd(uint64_t a, uint64_t b) {
    return a + b < a;
  }

  static inline bool cadc(uint64_t a, uint64_t b, bool c) {
    return a + b < a || (c && a + b == (uint64_t) -1);
  }

  bool check_hash_64(const crypto::hash &hash, const uint64_t difficulty) {
    uint64_t low, high, top, cur;
    // First check the highest word, this will most likely fail for a random hash.
    mul(swap64le(((const uint64_t *) &hash)[3]), difficulty, top, high);
    if (high != 0) {
      return false;
    }
    mul(swap64le(((const uint64_t *) &hash)[0]), difficulty, low, cur);
    mul(swap64le(((const uint64_t *) &hash)[1]), difficulty, low, high);
    bool carry = cadd(cur, low);
    cur = high;
    mul(swap64le(((const uint64_t *) &hash)[2]), difficulty, low, high);
    carry = cadc(cur, low, carry);
    carry = cadc(high, top, carry);
    return !carry;
  }

  const difficulty_type max64bit(std::numeric_limits<std::uint64_t>::max());
  const boost::multiprecision::uint256_t max128bit(std::numeric_limits<boost::multiprecision::uint128_t>::max());
  const boost::multiprecision::uint512_t max256bit(std::numeric_limits<boost::multiprecision::uint256_t>::max());

#define FORCE_FULL_128_BITS

  bool check_hash_128(const crypto::hash &hash, const difficulty_type difficulty) {
#ifndef FORCE_FULL_128_BITS
    // fast check
    if (difficulty >= max64bit && ((const uint64_t *) &hash)[3] > 0)
      return false;
#endif
    // usual slow check
    boost::multiprecision::uint512_t hashVal = 0;
#ifdef FORCE_FULL_128_BITS
    for(int i = 0; i < 4; i++) { // highest word is zero
#else
    for(int i = 1; i < 4; i++) { // highest word is zero
#endif
      hashVal <<= 64;
      hashVal |= swap64le(((const uint64_t *) &hash)[3 - i]);
    }
    return hashVal * difficulty <= max256bit;
  }

  bool check_hash(const crypto::hash &hash, const difficulty_type difficulty) {
    if (difficulty <= max64bit) // if can convert to small difficulty - do it
      return check_hash_64(hash, difficulty.convert_to<std::uint64_t>());
    else
      return check_hash_128(hash, difficulty);
  }

  std::string hex(const difficulty_type _v)
  {
    static const char chars[] = "0123456789abcdef";
    std::string s;
    difficulty_type v = _v;
    while (v > 0)
      {
        s.push_back(chars[(v & 0xf).convert_to<unsigned>()]);
        v >>= 4;
      }
    if (s.empty())
      s += "0";
    std::reverse(s.begin(), s.end());
    return "0x" + s;
  }

  // LWMA-1 difficulty algorithm 
  // Copyright (c) 2017-2019 Zawy, MIT License
  // https://github.com/zawy12/difficulty-algorithms/issues/3
  const difficulty_type next_difficulty_v5
    (
     const std::vector<std::uint64_t> timestamps
     , const network_type m_nettype
     , const std::vector<difficulty_type> cumulative_difficulties
     , const uint64_t T
     , const uint64_t N
     , const uint64_t HEIGHT
     )
  {
    assert(timestamps.size() == cumulative_difficulties.size() && timestamps.size() <= N+1 );
    // assert(timestamps.size() == N+1);

    if (HEIGHT == 0) { return 1; }

    // 1 CPU can do 4e6 h/s ~= 2 ^ 22
    // diff for that is 2 ^ 22 * 300 (5 mins) ~= 2 ^ (22 + 8)
    // make it for 256 CPUs in case no one will be mining
    // 2 ^ (22 + 8 + 8) = 2 ^ 38 = 1 << 38
    const difficulty_type _b = 1;
    if (HEIGHT < N + 3) { return _b << 38; }

    uint64_t  L(0), i, this_timestamp(0), previous_timestamp(0);

    previous_timestamp = timestamps[0]-T;
    for ( i = 1; i <= N; i++) {
    // Safely prevent out-of-sequence timestamps
      if ( timestamps[i]  > previous_timestamp ) {   this_timestamp = timestamps[i];  }
      else {  this_timestamp = previous_timestamp+1;   }
      L +=  i*std::min(6*T ,this_timestamp - previous_timestamp);
      previous_timestamp = this_timestamp;
    }
    if (L < N*N*T/20 ) { L =  N*N*T/20; }

    const uint64_t avg_D =
      static_cast<uint64_t>(( cumulative_difficulties[N] - cumulative_difficulties[0] )/ N);

    // overflow bug fix
    const uint64_t avg_breakpoint = HEIGHT < 300 ?
      2000000*N*N*T : uint64_t(-1)/(N*(N+1)*T*99);

    // Prevent round off error for small D and overflow for large D.
    const uint64_t next_D = avg_D > avg_breakpoint ?
      avg_D/((200*L))*(N*(N+1)*T*99)
      : (avg_D*N*(N+1)*T*99)/(200*L);

    return  next_D;
  }
}
