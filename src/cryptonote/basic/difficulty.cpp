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

#include <limits>
#include <vector>

#include "tools/epee/include/int-util.h"
#include "tools/epee/include/misc_log_ex.h"
#include "math/crypto/hash.hpp"
#include "config/cryptonote.hpp"
#include "config/constant.hpp"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "difficulty"

namespace cryptonote {

  constexpr boost::multiprecision::uint512_t max256bit
  (std::numeric_limits<boost::multiprecision::uint256_t>::max());

  bool check_hash(const crypto::hash &hash, const diff_t difficulty) {
    // usual slow check
    boost::multiprecision::uint512_t hashVal = 0;
    for(int i = 0; i < 4; i++) { // highest word is zero
      hashVal <<= 64;
      hashVal |= swap64le(((const uint64_t *) &hash)[3 - i]);
    }
    return hashVal * difficulty <= max256bit;
  }

  // LWMA-1 difficulty algorithm 
  // Copyright (c) 2017-2019 Zawy, MIT License
  // https://github.com/zawy12/difficulty-algorithms/issues/3
  diff_t next_difficulty
    (
     const std::vector<std::uint64_t> timestamps
     , const network_type m_nettype
     , const std::vector<diff_t> cumulative_difficulties
     , const uint64_t HEIGHT
     )
  {
    constexpr uint64_t T = constant::DIFFICULTY_TARGET_IN_SECONDS;
    constexpr uint64_t N = constant::DIFFICULTY_WINDOW_IN_BLOCKS;

    CHECK_AND_ASSERT_THROW_MES
      (
       timestamps.size() == cumulative_difficulties.size() && timestamps.size() <= N+1
       , "timestamp size mismatch"
       );
    // assert(timestamps.size() == N+1);

    if (HEIGHT == 0) { return 1; }

    // constant initial diff for CPU farms which never came
    constexpr diff_t _b = 1;
    if (HEIGHT < N + 3) { return _b << 38; }

    uint64_t L_accummulator = 0;
    uint64_t previous_timestamp = timestamps[0] - T;

    for (uint64_t i = 1; i <= N; i++) {
      // Safely prevent out-of-sequence timestamps
      const uint64_t this_timestamp = std::max<uint64_t>(timestamps[i], previous_timestamp + 1);

      L_accummulator += i * std::min<uint64_t>( 6 * T, this_timestamp - previous_timestamp );
      previous_timestamp = this_timestamp;
    }

    const uint64_t L = std::max<uint64_t>(L_accummulator, N * N * T / 20);


    using namespace boost::multiprecision;

    const uint256_t avg_D =
      uint256_t( cumulative_difficulties[N] - cumulative_difficulties[0] ) / uint256_t(N);
    constexpr uint256_t n_n_plus_1_t_99 = N * (N + 1) * T * 99;
    const uint256_t l_200 = 200 * L;
    const uint256_t up = avg_D * n_n_plus_1_t_99;
    constexpr uint64_t overflow_until_height = 279;

    const uint256_t next_D =
      HEIGHT < overflow_until_height ?
      // overflow bug fix
      uint256_t(uint64_t(up)) / l_200
      : up / l_200;

    constexpr uint256_t max128bit(std::numeric_limits<uint128_t>::max());
    CHECK_AND_ASSERT_THROW_MES(next_D <= max128bit, "next_D overflowed 128bit unsigned int");

    return uint128_t(next_D);
  }

  std::string hex(const diff_t _v)
  {
    constexpr char chars[] = "0123456789abcdef";
    std::string s;
    diff_t v = _v;
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
}
