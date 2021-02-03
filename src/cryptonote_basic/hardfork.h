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

#pragma once

#include "syncobj.h"
#include "hardforks/hardforks.h"
#include "cryptonote_basic/cryptonote_basic.h"

namespace cryptonote
{
  class BlockchainDB;

  class HardFork
  {
  public:
    typedef enum {
      Ready,
    } State;

    HardFork(cryptonote::BlockchainDB &db, uint8_t original_version = 17, uint64_t original_version_till_height = 0, uint64_t window_size = 10080);

    bool add_fork(uint8_t version, uint64_t height, uint8_t threshold, time_t time);
    bool add_fork(uint8_t version, uint64_t height, time_t time);
    bool check(const cryptonote::block &block) const;
    bool check_for_height(const cryptonote::block &block, uint64_t height) const;
    bool add(const cryptonote::block &block, uint64_t height);
    bool reorganize_from_block_height(uint64_t height);
    bool reorganize_from_chain_height(uint64_t height);
    void on_block_popped(uint64_t new_chain_height);
    State get_state(time_t t) const;
    State get_state() const;
    uint8_t get(uint64_t height) const;
    uint8_t get_ideal_version() const;
    uint8_t get_ideal_version(uint64_t height) const;
    uint8_t get_next_version() const;
    uint8_t get_current_version() const;
    uint64_t get_earliest_ideal_height_for_version(uint8_t version) const;
    bool get_voting_info(uint8_t version, uint32_t &window, uint32_t &votes, uint32_t &threshold, uint64_t &earliest_height, uint8_t &voting) const;
  };

}  // namespace cryptonote

