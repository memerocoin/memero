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

#include <cstddef>
#include <cstdint>
#include <utility>

#include "config/lol.hpp"

namespace wallet {
namespace logic {
namespace functional {
namespace fee {

  size_t estimate_rct_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size);

  size_t estimate_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size);

  uint64_t estimate_tx_weight(int n_inputs, int mixin, int n_outputs, size_t extra_size);

  uint64_t calculate_fee_from_weight(uint64_t base_fee, uint64_t weight, uint64_t fee_multiplier, uint64_t fee_quantization_mask);

  uint64_t estimate_fee(int n_inputs, int mixin, int n_outputs, size_t extra_size, uint64_t base_fee, uint64_t fee_multiplier, uint64_t fee_quantization_mask);

  std::pair<size_t, uint64_t> estimate_tx_size_and_weight(int n_inputs, int n_outputs, size_t extra_size);

  constexpr uint64_t get_fee_multiplier(const uint32_t priority)
  {
    if (priority == 0) { return 1; };

    constexpr uint64_t multipliers[] = {1, 5, 25, 1000};
    constexpr size_t multiplier_length = sizeof(multipliers) / sizeof(multipliers[0]);

    const size_t i = priority - 1;
    if (i >= multiplier_length) { return 1; };

    return multipliers[i];
  }

  consteval uint64_t get_base_fee()
  {
    return constant::FEE_PER_BYTE;
  }

} // fee
} // functional
} // logic
} // wallet
