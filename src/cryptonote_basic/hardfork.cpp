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

#include <algorithm>
#include <cstdio>

#include "cryptonote_basic/cryptonote_basic.h"
#include "blockchain_db/blockchain_db.h"
#include "hardfork.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "hardfork"

using namespace cryptonote;

static uint8_t get_block_version(const cryptonote::block &b)
{
  return b.major_version;
}

HardFork::HardFork(cryptonote::BlockchainDB &db, uint8_t original_version, uint64_t original_version_till_height, uint64_t window_size):
  db(db),
  original_version(original_version),
  original_version_till_height(original_version_till_height),
  window_size(window_size),
  current_fork_index(0)
{
}

bool HardFork::add_fork(uint8_t version, uint64_t height, uint8_t threshold, time_t time)
{
  CRITICAL_REGION_LOCAL(lock);

  // add in order
  if (version == 0)
    return false;
  if (!heights.empty()) {
    if (version <= heights.back().version)
      return false;
    if (height <= heights.back().height)
      return false;
    if (time <= heights.back().time)
      return false;
  }
  if (threshold > 100)
    return false;
  heights.push_back(hardfork_t(version, height, threshold, time));
  return true;
}

bool HardFork::add_fork(uint8_t version, uint64_t height, time_t time)
{
  return add_fork(version, height, 0, time);
}

uint8_t HardFork::get_effective_version(uint8_t voting_version) const
{
  if (!heights.empty()) {
    uint8_t max_version = heights.back().version;
    if (voting_version > max_version)
      voting_version = max_version;
  }
  return voting_version;
}

bool HardFork::check(const cryptonote::block &block) const
{
  CRITICAL_REGION_LOCAL(lock);
  return ::get_block_version(block) == heights[current_fork_index].version;
}

bool HardFork::check_for_height(const cryptonote::block &block, uint64_t height) const
{
  CRITICAL_REGION_LOCAL(lock);
  int fork_index = get_next_fork_index(height);
  return ::get_block_version(block) == heights[fork_index].version;
}

bool HardFork::add(const cryptonote::block& block, uint64_t height)
{
  CRITICAL_REGION_LOCAL(lock);

  if (!check(block))
    return false;

  db.set_hard_fork_version(height, heights[current_fork_index].version);

  return true;
}

void HardFork::init()
{
  CRITICAL_REGION_LOCAL(lock);

  // add a placeholder for the default version, to avoid special cases
  if (heights.empty())
    heights.push_back(hardfork_t(original_version, 0, 0, 0));

  current_fork_index = 0;

  // restore state from DB
  uint64_t height = db.height();
  if (height > window_size)
    height -= window_size - 1;
  else
    height = 1;

  rescan_from_chain_height(height);
  MDEBUG("init done");
}

uint8_t HardFork::get_block_version(uint64_t height) const
{
  if (height <= original_version_till_height)
    return original_version;

  const cryptonote::block &block = db.get_block_from_height(height);
  return ::get_block_version(block);
}

bool HardFork::reorganize_from_block_height(uint64_t height)
{
  CRITICAL_REGION_LOCAL(lock);
  if (height >= db.height())
    return false;

  bool stop_batch = db.batch_start();

  const uint64_t rescan_height = height >= (window_size - 1) ? height - (window_size  -1) : 0;
  const uint8_t start_version = height == 0 ? original_version : db.get_hard_fork_version(height);
  while (current_fork_index > 0 && heights[current_fork_index].version > start_version) {
    --current_fork_index;
  }
  for (uint64_t h = rescan_height; h <= height; ++h) {
    cryptonote::block b = db.get_block_from_height(h);
  }

  uint8_t voted = get_next_fork_index(height + 1);
  if (voted > current_fork_index) {
    current_fork_index = voted;
  }

  const uint64_t bc_height = db.height();
  for (uint64_t h = height + 1; h < bc_height; ++h) {
    add(db.get_block_from_height(h), h);
  }

  if (stop_batch)
    db.batch_stop();

  return true;
}

bool HardFork::reorganize_from_chain_height(uint64_t height)
{
  if (height == 0)
    return false;
  return reorganize_from_block_height(height - 1);
}

bool HardFork::rescan_from_block_height(uint64_t height)
{
  CRITICAL_REGION_LOCAL(lock);
  db_rtxn_guard rtxn_guard(&db);
  if (height >= db.height())
    return false;

  for (uint64_t h = height; h < db.height(); ++h) {
    cryptonote::block b = db.get_block_from_height(h);
  }

  uint8_t lastv = db.get_hard_fork_version(db.height() - 1);
  current_fork_index = 0;
  while (current_fork_index + 1 < heights.size() && heights[current_fork_index].version != lastv)
    ++current_fork_index;

  uint8_t voted = get_next_fork_index(db.height());
  if (voted > current_fork_index) {
    current_fork_index = voted;
  }

  return true;
}

bool HardFork::rescan_from_chain_height(uint64_t height)
{
  if (height == 0)
    return false;
  return rescan_from_block_height(height - 1);
}

void HardFork::on_block_popped(uint64_t nblocks)
{
  CHECK_AND_ASSERT_THROW_MES(nblocks > 0, "nblocks must be greater than 0");

  CRITICAL_REGION_LOCAL(lock);

  const uint64_t new_chain_height = db.height();
  const uint64_t old_chain_height = new_chain_height + nblocks;
  uint8_t version;
  for (uint64_t height = old_chain_height - 1; height >= new_chain_height; --height)
  {
    version = db.get_hard_fork_version(height);
  }

  // does not take voting into account
  for (current_fork_index = heights.size() - 1; current_fork_index > 0; --current_fork_index)
    if (new_chain_height >= heights[current_fork_index].height)
      break;
}

int HardFork::get_next_fork_index(uint64_t height) const
{
  CRITICAL_REGION_LOCAL(lock);
  uint32_t accumulated_votes = 0;
  for (int n = heights.size() - 1; n >= 0; --n) {
    uint8_t v = heights[n].version;
    if (height >= heights[n].height) {
      return n;
    }
  }
  return current_fork_index;
}

HardFork::State HardFork::get_state(time_t t) const
{
  CRITICAL_REGION_LOCAL(lock);

  // no hard forks setup yet
  if (heights.size() <= 1)
    return Ready;

  time_t t_last_fork = heights.back().time;
  return Ready;
}

HardFork::State HardFork::get_state() const
{
  return get_state(time(NULL));
}

uint8_t HardFork::get(uint64_t height) const
{
  CRITICAL_REGION_LOCAL(lock);
  if (height > db.height()) {
    assert(false);
    return 255;
  }
  if (height == db.height()) {
    return get_current_version();
  }
  return db.get_hard_fork_version(height);
}

uint8_t HardFork::get_current_version() const
{
  CRITICAL_REGION_LOCAL(lock);
  return heights[current_fork_index].version;
}

uint8_t HardFork::get_ideal_version() const
{
  CRITICAL_REGION_LOCAL(lock);
  return heights.back().version;
}

uint8_t HardFork::get_ideal_version(uint64_t height) const
{
  CRITICAL_REGION_LOCAL(lock);
  for (unsigned int n = heights.size() - 1; n > 0; --n) {
    if (height >= heights[n].height) {
      return heights[n].version;
    }
  }
  return original_version;
}

uint64_t HardFork::get_earliest_ideal_height_for_version(uint8_t version) const
{
  uint64_t height = std::numeric_limits<uint64_t>::max();
  for (auto i = heights.rbegin(); i != heights.rend(); ++i) {
    if (i->version >= version) {
      height = i->height;
    } else {
      break;
    }
  }
  return height;
}

uint8_t HardFork::get_next_version() const
{
  CRITICAL_REGION_LOCAL(lock);
  uint64_t height = db.height();
  for (auto i = heights.rbegin(); i != heights.rend(); ++i) {
    if (height >= i->height) {
      return (i == heights.rbegin() ? i : (i - 1))->version;
    }
  }
  return original_version;
}

bool HardFork::get_voting_info(uint8_t version, uint32_t &window, uint32_t &votes, uint32_t &threshold, uint64_t &earliest_height, uint8_t &voting) const
{
  CRITICAL_REGION_LOCAL(lock);

  const uint8_t current_version = heights[current_fork_index].version;
  const bool enabled = current_version >= version;
  votes = 0;
  threshold = 0;
  //assert((votes >= threshold) == enabled);
  earliest_height = get_earliest_ideal_height_for_version(version);
  voting = heights.back().version;
  return enabled;
}

