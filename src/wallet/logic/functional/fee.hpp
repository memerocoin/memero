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

#include "tools/epee/include/logging.hpp"

#include "config/lol.hpp"

namespace wallet {
namespace logic {
namespace functional {
namespace fee {

  //----------------------------------------------------------------------------------------------------
  constexpr size_t estimate_rct_tx_size
  (
   const int n_inputs
   , const int mixin
   , const int n_outputs
   , const size_t extra_size
   )
  {
    size_t size = 0;
    // tx prefix

    // first few bytes
    size += 1 + 6;

    // vin
    size += n_inputs * (1+6+(mixin+1)*2+32);

    // vout
    size += n_outputs * (6+32);

    // extra
    size += extra_size;

    // rct signatures

    // type
    size += 1;

    // rangeSigs
    {
      size_t log_padded_outputs = 0;
      while ((1<<log_padded_outputs) < n_outputs)
        ++log_padded_outputs;
      size += (2 * (6 + log_padded_outputs) + 4 + 5) * 32 + 3;
    }

    // MGs/CLSAGs
    size += n_inputs * (32 * (mixin+1) + 64);

    // decoys - not serialized, can be reconstructed
    /* size += 2 * 32 * (mixin+1) * n_inputs; */

    // pseudo_commits
    size += 32 * n_inputs;
    // ecdh
    size += 8 * n_outputs;
    // outPk - only commitment is saved
    size += 32 * n_outputs;
    // fee
    size += 4;

    // LOG_PRINT_L2
    //   (
    //    "estimated rct tx size for " << n_inputs <<
    //    " inputs with ring size " << (mixin+1) <<
    //    " and " << n_outputs <<
    //    " outputs: " << size <<
    //    " (" << ((32 * n_inputs/*+1*/) + 2 * 32 * (mixin+1) * n_inputs + 32 * n_outputs) << " saved)"
    //    );
    return size;
  }

  //----------------------------------------------------------------------------------------------------
  constexpr size_t estimate_tx_size(const int n_inputs, const int mixin, const int n_outputs, const size_t extra_size)
  {
    return estimate_rct_tx_size(n_inputs, mixin, n_outputs, extra_size);
  }

  //----------------------------------------------------------------------------------------------------
  constexpr uint64_t estimate_tx_weight(const int n_inputs, const int mixin, const int n_outputs, const size_t extra_size)
  {
    return estimate_tx_size(n_inputs, mixin, n_outputs, extra_size);
  }

  //----------------------------------------------------------------------------------------------------
  constexpr uint64_t calculate_fee_from_weight
  (
   const uint64_t base_fee
   , const uint64_t weight
   , const uint64_t fee_multiplier
   , const uint64_t fee_quantization_mask
   )
  {
    const uint64_t fee = weight * base_fee * fee_multiplier;
    return (fee + fee_quantization_mask - 1) / fee_quantization_mask * fee_quantization_mask;
  }

  //----------------------------------------------------------------------------------------------------
  constexpr uint64_t estimate_fee
  (
   const int n_inputs
   , const int mixin
   , const int n_outputs
   , const size_t extra_size
   , const uint64_t base_fee
   , const uint64_t fee_multiplier
   , const uint64_t fee_quantization_mask
   )
  {
    const size_t estimated_tx_weight = estimate_tx_weight(n_inputs, mixin, n_outputs, extra_size);
    return calculate_fee_from_weight(base_fee, estimated_tx_weight, fee_multiplier, fee_quantization_mask);
  }

  std::pair<size_t, uint64_t> estimate_tx_size_and_weight
  (
   const int n_inputs
   , const int n_outputs
   , const size_t extra_size
   );

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
