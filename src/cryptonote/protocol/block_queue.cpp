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

#include "block_queue.h"

#include "cryptonote_protocol_defs.h"

#include "tools/epee/include/syncobj.h"

#include <boost/uuid/uuid_io.hpp>

#include <numeric>


namespace cryptonote
{

  std::mutex batch_mutex;

  void block_queue::add_blocks
  (
   const uint64_t height
   , const std::span<const cryptonote::block_complete_entry> xs
   , const boost::uuids::uuid connection_id
   , const epee::net_utils::network_address addr
   , const float rate
   , const size_t size
   )
  {
    if (xs.empty()) return;

    LOCK_MUTEX(batch_mutex);
    batches.emplace_back(height, xs, connection_id, addr, rate, size);
  }


  void block_queue::remove_batches_from_connection
  (
   const boost::uuids::uuid connection_id
   )
  {
    LOCK_MUTEX(batch_mutex);
    batchV new_batches;

    for (const auto& x: batches) {
      if(x.connection_id != connection_id) {
        new_batches.push_back(x);
      }
    }

    batches = new_batches;
  }

  void block_queue::remove_batches_from_connection
  (
   const boost::uuids::uuid connection_id
   , const uint64_t start_block_height
   )
  {
    LOCK_MUTEX(batch_mutex);
    batchV new_batches;

    for (const auto& x: batches) {
      if (x.connection_id == connection_id
          && x.start_block_height <= start_block_height)
        {
        }
      else {
        new_batches.push_back(x);
      }
    }

    batches = new_batches;
  }


  std::optional<std::pair<uint64_t, uint64_t>>
  block_queue::reserve_blocks
  (
   const uint64_t first_block_height
   , const uint64_t last_block_height
   , const uint64_t max_blocks
   , const boost::uuids::uuid &connection_id
   , const epee::net_utils::network_address &addr
   , const uint64_t blockchain_height
   , const std::span<std::pair<crypto::hash, uint64_t>> block_hashes
   , const std::chrono::time_point<std::chrono::system_clock> time
   ) const
  {
    LOCK_MUTEX(batch_mutex);

    LOG_DEBUG
      (
       "reserve_blocks: first_block_height "
       + std::to_string(first_block_height)
       + ", last_block_height "
       + std::to_string(last_block_height)
       + ", max "
       + std::to_string(max_blocks)
       + ", blockchain_height "
       + std::to_string(blockchain_height)
       + ", block hashes size "
       + std::to_string(block_hashes.size())
       );

    if (last_block_height < first_block_height || max_blocks == 0)
      {
        LOG_DEBUG
          (
           "reserve_blocks: early out: first_block_height "
           + std::to_string(first_block_height)
           + ", last_block_height "
           + std::to_string(last_block_height)
           + ", max_blocks "
           + std::to_string(max_blocks)
           );
        return {};
      }
    if (block_hashes.size() > last_block_height)
      {
        LOG_DEBUG
          (
           "reserve_blocks: more block hashes than fit within last_block_height: "
           + std::to_string(block_hashes.size())
           + " and "
           + std::to_string(last_block_height)
           );
        return {};
      }

    // skip everything we've already requested
    const uint64_t span_start_height =
      last_block_height - block_hashes.size() + 1;


    LOG_DEBUG("span_start_height: " + std::to_string(span_start_height));

    const uint64_t block_hashes_start_height =
      last_block_height - block_hashes.size() + 1;

    if (span_start_height >= block_hashes.size() + block_hashes_start_height)
      {
        LOG_DEBUG("Out of hashes, cannot reserve");
        return {};
      }

    auto i = std::next
      (
       block_hashes.begin()
       , span_start_height - block_hashes_start_height
       );

    uint64_t span_length = 0;
    while (i != block_hashes.end() && span_length < max_blocks)
      {
        ++i;
        ++span_length;
      }

    if (span_length == 0)
      {
        LOG_DEBUG_MUTE("span_length 0, cannot reserve");
        return {};
      }

    LOG_DEBUG
      (
       "Reserving span "
       + std::to_string(span_start_height)
       + " - "
       + std::to_string(span_start_height + span_length - 1)
       + " for "
       + boost::uuids::to_string(connection_id)
       );
    return {std::make_pair(span_start_height, span_length)};
  }

  std::optional<std::pair<uint64_t, uint64_t>>
  block_queue::get_next_span_if_scheduled() const
  {
    LOCK_MUTEX(batch_mutex);
    if (batches.empty()) return {};

    const auto& x = batches.front();

    return {{x.start_block_height, x.blocks.size()}};
  }

  void block_queue::reset_next_batch_time
  (const std::chrono::time_point<std::chrono::system_clock> t)
  {
    LOCK_MUTEX(batch_mutex);
    if (batches.empty()) return;

    batches.front().time = t;
  }

  std::optional
  <
    std::tuple
    <
      uint64_t
      , std::vector<cryptonote::block_complete_entry>
      , boost::uuids::uuid
      , epee::net_utils::network_address
      >>
  block_queue::get_next_batch () const
  {
    LOCK_MUTEX(batch_mutex);

    if (batches.empty())
      return {};

    const auto& x = batches.front();

    return
      {{
          x.start_block_height
          , x.blocks
          , x.connection_id
          , x.origin
        }};
  }

  bool block_queue::has_next_batch(const uint64_t height) const
  {
    LOCK_MUTEX(batch_mutex);
    if (batches.empty())
      return false;

    return batches.front().start_block_height <= height;
  }

}
