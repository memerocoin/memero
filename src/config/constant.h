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
  const uint64_t CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V2 = 300*2;
  const size_t BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2 = 11;

  // MONEY_SUPPLY - total number coins to be generated
  const uint64_t MONEY_SUPPLY = (uint64_t)(-1);

  // COIN - number of smallest units in one coin
  const uint64_t COIN = (uint64_t)100000000000; // pow(10, 11)
  const size_t CRYPTONOTE_REWARD_BLOCKS_WINDOW = 100;

  //size of block (bytes) after which reward for block calculated using block size - second change, from v5
  const uint64_t CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 = 300000;

  const uint64_t FEE_PER_BYTE = (uint64_t)300000;
  const uint64_t DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT = (uint64_t)3000;

  const uint64_t DIFFICULTY_TARGET_V2 = 300;
  const uint64_t DIFFICULTY_WINDOW_V3 = 144;
  const uint64_t DIFFICULTY_BLOCKS_COUNT_V3 = DIFFICULTY_WINDOW_V3 + 1;

  const uint64_t CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS = 1;
  const uint64_t CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2 =
    DIFFICULTY_TARGET_V2 * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS;

}
