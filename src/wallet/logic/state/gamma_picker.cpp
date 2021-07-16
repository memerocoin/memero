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

#include "gamma_picker.hpp"

#include "wallet/api/wallet_errors.h"


namespace wallet {
namespace logic {
namespace state {

  const double GAMMA_SHAPE = 19.28;
  constexpr double GAMMA_SCALE = 1.0/1.61;

  gamma_picker::gamma_picker(const std::vector<uint64_t> &rct_offsets, double shape, double scale):
      rct_offsets(rct_offsets)
  {
    gamma = std::gamma_distribution<double>(shape, scale);
    THROW_WALLET_EXCEPTION_IF(rct_offsets.size() <= CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE, tools::error::wallet_internal_error, "Bad offset calculation");
    const size_t blocks_in_a_year = 86400 * 365 / constant::DIFFICULTY_TARGET_IN_SECONDS;
    const size_t blocks_to_consider = std::min<size_t>(rct_offsets.size(), blocks_in_a_year);
    const size_t outputs_to_consider = rct_offsets.back() -
      (blocks_to_consider < rct_offsets.size() ? rct_offsets[rct_offsets.size() - blocks_to_consider - 1] : 0);
    begin = rct_offsets.data();
    end = rct_offsets.data() + rct_offsets.size() - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
    num_rct_outputs = *(end - 1);
    THROW_WALLET_EXCEPTION_IF(num_rct_outputs == 0, tools::error::wallet_internal_error, "No rct outputs");

    average_output_time = constant::DIFFICULTY_TARGET_IN_SECONDS * blocks_to_consider /
      static_cast<double>(outputs_to_consider); // this assumes constant target over the whole rct range
  };

  gamma_picker::gamma_picker(const std::vector<uint64_t> &rct_offsets): gamma_picker(rct_offsets, GAMMA_SHAPE, GAMMA_SCALE) {}

  uint64_t gamma_picker::pick()
  {
    double x = gamma(engine);
    x = exp(x);
    uint64_t output_index = x / average_output_time;
    if (output_index >= num_rct_outputs)
      return std::numeric_limits<uint64_t>::max(); // bad pick
    output_index = num_rct_outputs - 1 - output_index;

    const uint64_t *it = std::lower_bound(begin, end, output_index);
    THROW_WALLET_EXCEPTION_IF(it == end, tools::error::wallet_internal_error, "output_index not found");
    uint64_t index = std::distance(begin, it);

    const uint64_t first_rct = index == 0 ? 0 : rct_offsets[index - 1];
    const uint64_t n_rct = rct_offsets[index] - first_rct;
    if (n_rct == 0)
      return std::numeric_limits<uint64_t>::max(); // bad pick
    MTRACE("Picking 1/" << n_rct << " in block " << index);
    return first_rct + crypto::rand_idx(n_rct);
  };

} // state
} // logic
} // wallet
