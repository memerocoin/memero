/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "difficulty.h"

#include "tools/epee/include/misc_log_ex.h"




#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "difficulty"

namespace cryptonote {

  boost::multiprecision::uint512_t hash_to_int(const crypto::hash &hash) {
    boost::multiprecision::uint512_t v;
    boost::multiprecision::import_bits(v, std::begin(hash.data), std::end(hash.data), 0, false);
    return v;
  }

  bool check_hash(const crypto::hash &hash, const diff_t difficulty) {
    return check_hash_int(hash_to_int(hash), difficulty);
  }

  diff_t next_difficulty
    (
     const std::vector<std::uint64_t> timestamps
     , const std::vector<diff_t> cumulative_difficulties
     , const uint64_t HEIGHT
     )
  {
    constexpr uint64_t N = constant::DIFFICULTY_WINDOW_IN_BLOCKS;

    LOG_ERROR_AND_THROW_UNLESS
      (
       timestamps.size() == cumulative_difficulties.size()
       , "timestamp size mismatch"
       );

    if (HEIGHT == 0) { return 1; }

    // constant initial diff for CPU farms which never came
    constexpr diff_t _b = 1;
    if (HEIGHT < N + 3) { return _b << 38; }


    LOG_ERROR_AND_THROW_UNLESS
      (
       timestamps.size() == constant::DIFFICULTY_BLOCKS_COUNT
       , "timestamp size is invalid"
       );

    std::array<std::uint64_t, constant::DIFFICULTY_BLOCKS_COUNT> timestamps_array;
    std::copy_n(timestamps.begin(), constant::DIFFICULTY_BLOCKS_COUNT, timestamps_array.begin());

    std::array<diff_t, constant::DIFFICULTY_BLOCKS_COUNT> cumulative_difficulties_array;
    std::copy_n(cumulative_difficulties.begin(), constant::DIFFICULTY_BLOCKS_COUNT, cumulative_difficulties_array.begin());

    const diff_t next = next_difficulty_pure(timestamps_array, cumulative_difficulties_array, HEIGHT);

    LOG_ERROR_AND_THROW_UNLESS(next > 0, "next difficulty overflowed 128bit unsigned int");
    return next;
  }

  std::string diff_to_hex(const diff_t _v)
  {
    std::stringstream stream;
    stream << std::hex << _v;
    return "0x" + stream.str();
  }
}
