// Copyright (c) 2017-2020, The Monero Project
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

#include "tools/epee/include/net/net_utils_base.h"
#include "math/hash/functional/hash.hpp"

#include "cryptonote_protocol_defs.h"

#include <unordered_set>


namespace cryptonote
{
  struct block_batch
  {
    uint64_t start_block_height;
    std::vector<cryptonote::block_complete_entry> blocks;
    boost::uuids::uuid connection_id;
    float block_rate;
    size_t data_size;
    std::chrono::time_point<std::chrono::system_clock> time;
    epee::net_utils::network_address origin{};

    block_batch
    (
     const uint64_t start_block_height
     , const std::span<const cryptonote::block_complete_entry> blocks
     , const boost::uuids::uuid &connection_id
     , const epee::net_utils::network_address &addr
     , const float block_rate
     , const size_t data_size
     ):
      start_block_height(start_block_height)
      , blocks({blocks.begin(), blocks.end()})
      , connection_id(connection_id)
      , block_rate(block_rate)
      , data_size(data_size)
      , time(std::chrono::time_point<std::chrono::system_clock>::min())
      , origin(addr)
    {}

  };

  struct block_queue
  {
    using batchV = std::list<block_batch>;
    batchV batches;

    void add_blocks
    (
     const uint64_t height
     , const std::span<const cryptonote::block_complete_entry> xs
     , const boost::uuids::uuid &connection_id
     , const epee::net_utils::network_address &addr
     , const float rate
     , const size_t size
     );

    void remove_batches_from_connection
    (
     const boost::uuids::uuid connection_id
     );

    void remove_batches_from_connection
    (
     const boost::uuids::uuid connection_id
     , const uint64_t start_block_height
     );

    std::optional<std::pair<uint64_t, uint64_t>> reserve_blocks
    (
     const uint64_t first_block_height
     , const uint64_t last_block_height
     , const uint64_t max_blocks
     , const boost::uuids::uuid &connection_id
     , const epee::net_utils::network_address &addr
     , const uint64_t blockchain_height
     , const std::vector<std::pair<crypto::hash, uint64_t>> &block_hashes
     , const std::chrono::time_point<std::chrono::system_clock> time
     = std::chrono::system_clock::now()
     ) const;

    std::optional<std::pair<uint64_t, uint64_t>>
    get_next_span_if_scheduled() const;

    void reset_next_batch_time
    (
     const std::chrono::time_point<std::chrono::system_clock> t
     = std::chrono::system_clock::now()
     );

    bool get_next_batch
    (
     uint64_t &height
     , std::vector<cryptonote::block_complete_entry> &bcel
     , boost::uuids::uuid &connection_id
     , epee::net_utils::network_address &addr
     ) const;

    bool has_next_batch(const uint64_t height) const;

  };
}
