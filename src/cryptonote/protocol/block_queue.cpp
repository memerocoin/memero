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

#include <boost/uuid/uuid_io.hpp>

#include <numeric>


namespace cryptonote
{

  std::recursive_mutex mutex;

void block_queue::add_blocks(uint64_t height, std::vector<cryptonote::block_complete_entry> bcel, const boost::uuids::uuid &connection_id, const epee::net_utils::network_address &addr, float rate, size_t size)
{
  const std::unique_lock<std::recursive_mutex> lock(mutex);
  std::vector<crypto::hash> hashes;
  batches.emplace_back(height, std::move(bcel), connection_id, addr, rate, size);
}

void block_queue::add_blocks(uint64_t height, uint64_t nblocks, const boost::uuids::uuid &connection_id, const epee::net_utils::network_address &addr, std::chrono::time_point<std::chrono::system_clock> time)
{
  LOG_ERROR_AND_THROW_UNLESS(nblocks > 0, "Empty span");
  const std::unique_lock<std::recursive_mutex> lock(mutex);
  batches.push_back(batch(height, nblocks, connection_id, addr, time));
}

void block_queue::flush_spans(const boost::uuids::uuid &connection_id, bool all)
{
  const std::unique_lock<std::recursive_mutex> lock(mutex);
  batchV::iterator i = batches.begin();
  while (i != batches.end())
  {
    batchV::iterator j = i++;
    if (j->connection_id == connection_id && (all || j->blocks.size() == 0))
    {
      erase_block(j);
    }
  }
}

void block_queue::erase_block(batchV::iterator j)
{
  LOG_ERROR_AND_THROW_UNLESS(j != batches.end(), "Invalid iterator");
  batches.erase(j);
}

void block_queue::flush_stale_spans(const std::set<boost::uuids::uuid> &live_connections)
{
  const std::unique_lock<std::recursive_mutex> lock(mutex);
  batchV::iterator i = batches.begin();
  while (i != batches.end())
  {
    batchV::iterator j = i++;
    if (j->blocks.empty() && live_connections.find(j->connection_id) == live_connections.end())
    {
      erase_block(j);
    }
  }
}

void block_queue::remove_spans
(
 const boost::uuids::uuid connection_id
 , const uint64_t start_block_height
 )
{
  const std::unique_lock<std::recursive_mutex> lock(mutex);
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


uint64_t block_queue::get_max_block_height() const
{
  const std::unique_lock<std::recursive_mutex> lock(mutex);
  uint64_t height = 0;
  for (const auto &batch: batches)
  {
    const uint64_t h = batch.start_block_height + batch.nblocks - 1;
    if (h > height)
      height = h;
  }
  return height;
}

void block_queue::print() const
{
  const std::unique_lock<std::recursive_mutex> lock(mutex);
  LOG_DEBUG_MUTE
    (
     "Block queue has "
     + std::to_string(blocks.size())
     + " batches"
     );
}

std::pair<uint64_t, uint64_t> block_queue::reserve_span
(
 uint64_t first_block_height
 , uint64_t last_block_height
 , uint64_t max_blocks
 , const boost::uuids::uuid &connection_id
 , const epee::net_utils::network_address &addr
 , uint64_t blockchain_height
 , const std::vector<std::pair<crypto::hash, uint64_t>> &block_hashes
 , std::chrono::time_point<std::chrono::system_clock> time
 )
{
  const std::unique_lock<std::recursive_mutex> lock(mutex);

  LOG_DEBUG_MUTE("reserve_span: first_block_height " << first_block_height
         << ", last_block_height " << last_block_height
         << ", max " << max_blocks
         << ", blockchain_height " << blockchain_height
         << ", block hashes size " << block_hashes.size()
         );
  if (last_block_height < first_block_height || max_blocks == 0)
  {
    LOG_DEBUG_MUTE("reserve_span: early out: first_block_height " << first_block_height << ", last_block_height " << last_block_height << ", max_blocks " << max_blocks);
    return std::make_pair(0, 0);
  }
  if (block_hashes.size() > last_block_height)
  {
    LOG_DEBUG_MUTE("reserve_span: more block hashes than fit within last_block_height: " << block_hashes.size() << " and " << last_block_height);
    return std::make_pair(0, 0);
  }

  // skip everything we've already requested
  uint64_t span_start_height = last_block_height - block_hashes.size() + 1;
  std::vector<std::pair<crypto::hash, uint64_t>>::const_iterator i = block_hashes.begin();

  LOG_DEBUG_MUTE("span_start_height: " <<span_start_height);
  const uint64_t block_hashes_start_height = last_block_height - block_hashes.size() + 1;
  if (span_start_height >= block_hashes.size() + block_hashes_start_height)
  {
    LOG_DEBUG_MUTE("Out of hashes, cannot reserve");
    return std::make_pair(0, 0);
  }

  i = std::next(block_hashes.begin(), span_start_height - block_hashes_start_height);

  uint64_t span_length = 0;
  std::vector<crypto::hash> hashes;
  while (i != block_hashes.end() && span_length < max_blocks)
  {
    hashes.push_back((*i).first);
    ++i;
    ++span_length;
  }
  if (span_length == 0)
  {
    LOG_DEBUG_MUTE("span_length 0, cannot reserve");
    return std::make_pair(0, 0);
  }
  LOG_DEBUG_MUTE("Reserving span " << span_start_height << " - " << (span_start_height + span_length - 1) << " for " << connection_id);
  return std::make_pair(span_start_height, span_length);
}

std::pair<uint64_t, uint64_t> block_queue::get_next_span_if_scheduled(std::vector<crypto::hash> &hashes, boost::uuids::uuid &connection_id, std::chrono::time_point<std::chrono::system_clock> &time) const
{
  const std::unique_lock<std::recursive_mutex> lock(mutex);
  if (batches.empty())
    return std::make_pair(0, 0);
  batchV::const_iterator i = batches.begin();
  if (i == batches.end())
    return std::make_pair(0, 0);
  if (!i->blocks.empty())
    return std::make_pair(0, 0);
  connection_id = i->connection_id;
  time = i->time;
  return std::make_pair(i->start_block_height, i->nblocks);
}

void block_queue::reset_next_span_time(std::chrono::time_point<std::chrono::system_clock> t)
{
  const std::unique_lock<std::recursive_mutex> lock(mutex);
  LOG_ERROR_AND_THROW_UNLESS(!batches.empty(), "No next span to reset time");

  batchV::iterator i = batches.begin();
  LOG_ERROR_AND_THROW_UNLESS(i != batches.end(), "No next span to reset time");

  LOG_ERROR_AND_THROW_UNLESS(i->blocks.empty(), "Next span is not empty");
  (std::chrono::time_point<std::chrono::system_clock>&)i->time = t; // sod off, time doesn't influence sorting
}

bool block_queue::get_next_span(uint64_t &height, std::vector<cryptonote::block_complete_entry> &bcel, boost::uuids::uuid &connection_id, epee::net_utils::network_address &addr, bool filled) const
{
  const std::unique_lock<std::recursive_mutex> lock(mutex);
  if (batches.empty())
    return false;
  batchV::const_iterator i = batches.begin();
  for (; i != batches.end(); ++i)
  {
    if (!filled || !i->blocks.empty())
    {
      height = i->start_block_height;
      bcel = i->blocks;
      connection_id = i->connection_id;
      addr = i->origin;
      return true;
    }
  }
  return false;
}

bool block_queue::has_next_span(uint64_t height, bool &filled, std::chrono::time_point<std::chrono::system_clock> &time, boost::uuids::uuid &connection_id) const
{
  const std::unique_lock<std::recursive_mutex> lock(mutex);
  if (batches.empty())
    return false;
  batchV::const_iterator i = batches.begin();
  if (i == batches.end())
    return false;
  if (i->start_block_height > height)
    return false;
  filled = !i->blocks.empty();
  time = i->time;
  connection_id = i->connection_id;
  return true;
}

crypto::hash block_queue::get_last_known_hash(const boost::uuids::uuid &connection_id) const
{
  return {};
}

}
