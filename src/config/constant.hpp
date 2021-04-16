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

#include <cstdint>
#include <cstdlib>

namespace constant
{
  // MONEY_SUPPLY - total number coins to be generated
  constexpr uint64_t MONEY_SUPPLY = (uint64_t)(-1);

  // COIN - number of smallest units in one coin
  constexpr uint64_t COIN = 100000000000u; // pow(10, 11)

  constexpr uint64_t CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V2 = 300*2;
  constexpr size_t BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2 = 11;

  constexpr uint64_t FEE_PER_BYTE = 300000;

  constexpr uint64_t DIFFICULTY_TARGET_IN_SECONDS = 300;
  constexpr uint64_t DIFFICULTY_WINDOW_IN_BLOCKS = 144;
  constexpr uint64_t DIFFICULTY_BLOCKS_COUNT = DIFFICULTY_WINDOW_IN_BLOCKS + 1;

  constexpr uint64_t CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS = 1;
  constexpr uint64_t CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2 =
    DIFFICULTY_TARGET_IN_SECONDS * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS;


  constexpr uint64_t RPC_IP_FAILS_BEFORE_BLOCK = 3;
  constexpr size_t PER_KB_FEE_QUANTIZATION_DECIMALS = 8;
  constexpr size_t DEFAULT_TXPOOL_MAX_WEIGHT = 648000000; // 3 days at 300000, in bytes
  constexpr size_t BULLETPROOF_MAX_OUTPUTS = 16;
}
