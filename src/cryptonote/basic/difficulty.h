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

#pragma once

#include "math/crypto/hash.hpp"

#include "config/network.hpp"
#include "config/lol.hpp"

#include <cstdint>
#include <vector>
#include <string>
#include <numeric>

#include <boost/multiprecision/cpp_int.hpp>


namespace cryptonote
{
  typedef boost::multiprecision::uint128_t diff_t;

  constexpr boost::multiprecision::uint512_t max256bit
  (std::numeric_limits<boost::multiprecision::uint256_t>::max());

  constexpr boost::multiprecision::uint512_t max_int_for_diff(const diff_t difficulty) {
    return max256bit / difficulty;
  }

  constexpr bool check_hash_int(const boost::multiprecision::uint512_t hashInt, const diff_t difficulty) {
    return hashInt * difficulty <= max256bit;
  }

  // LWMA-1 difficulty algorithm
  // Copyright (c) 2017-2019 Zawy, MIT License
  // https://github.com/zawy12/difficulty-algorithms/issues/3
  constexpr diff_t next_difficulty_pure
  (
   const std::array<std::uint64_t, constant::DIFFICULTY_BLOCKS_COUNT> timestamps
   , const std::array<diff_t, constant::DIFFICULTY_BLOCKS_COUNT> cumulative_difficulties
   , const uint64_t HEIGHT
   )
  {
    constexpr uint64_t T = constant::DIFFICULTY_TARGET_IN_SECONDS;
    constexpr uint64_t N = constant::DIFFICULTY_WINDOW_IN_BLOCKS;

    struct L_collector {
      uint64_t linear_index;
      uint64_t sum;
      uint64_t last;
    };

    auto accumulate_linearly_weighted_timestamp_diff =
      [](const L_collector x, const uint64_t t) -> L_collector
      {
        constexpr uint64_t maximum_allowed_time_diff = 6 * T;
        constexpr uint64_t dt = 1;

        const bool is_past_solve_time = t <= x.last;
        const uint64_t accepted_time_diff =
          is_past_solve_time ? dt : std::min<uint64_t>( t - x.last, maximum_allowed_time_diff );

        const uint64_t weight = x.linear_index * accepted_time_diff;

        const uint64_t accepted_timestamp = is_past_solve_time ? x.last + dt : t;

        return L_collector{ x.linear_index + 1, x.sum + weight, accepted_timestamp };
      };


    // potential bug here, timestamps[0] should already be T seconds away from timestamps[1]
    // but not worth fixing, since it's a surplus at the least significant weight index, should
    // affect less than 1 second of target (28ms?), so not really observable.
    const L_collector l_init{ 1, 0, timestamps.front() - T };

    const L_collector l_collector = std::accumulate
     (
       std::next(timestamps.begin())
       , timestamps.end()
       , l_init
       , accumulate_linearly_weighted_timestamp_diff
       );

    constexpr uint64_t min_weight = N * N * T / 20;
    const uint64_t L = std::max<uint64_t>(l_collector.sum, min_weight);


    using namespace boost::multiprecision;

    const uint256_t avg_D =
      uint256_t( cumulative_difficulties.back() - cumulative_difficulties.front() ) / uint256_t(N);
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

    return next_D <= max128bit ? uint128_t(next_D) : 0;
  }


  boost::multiprecision::uint512_t hash_to_int(const crypto::hash &hash);
  bool check_hash(const crypto::hash &hash, const diff_t difficulty);

  diff_t next_difficulty
  (
   const std::vector<std::uint64_t> timestamps
   , const std::vector<diff_t> cumulative_difficulties
   , const uint64_t HEIGHT
   );

  std::string hex(const diff_t v);
}
