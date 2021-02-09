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


#include "fee.hpp"

#include "misc_log_ex.h"
#include "wallet/api/wallet_errors.h"

namespace wallet {
namespace logic {
namespace functional {
namespace fee {

  //----------------------------------------------------------------------------------------------------
  size_t estimate_rct_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size)
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

    // mixRing - not serialized, can be reconstructed
    /* size += 2 * 32 * (mixin+1) * n_inputs; */

    // pseudoOuts
    size += 32 * n_inputs;
    // ecdhInfo
    size += 8 * n_outputs;
    // outPk - only commitment is saved
    size += 32 * n_outputs;
    // txnFee
    size += 4;

    LOG_PRINT_L2("estimated rct tx size for " << n_inputs << " inputs with ring size " << (mixin+1) << " and " << n_outputs << " outputs: " << size << " (" << ((32 * n_inputs/*+1*/) + 2 * 32 * (mixin+1) * n_inputs + 32 * n_outputs) << " saved)");
    return size;
  }


  //----------------------------------------------------------------------------------------------------
  size_t estimate_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size)
  {
    return estimate_rct_tx_size(n_inputs, mixin, n_outputs, extra_size);
  }

  //----------------------------------------------------------------------------------------------------
  uint64_t estimate_tx_weight(int n_inputs, int mixin, int n_outputs, size_t extra_size)
  {
    return estimate_tx_size(n_inputs, mixin, n_outputs, extra_size);
  }

  //----------------------------------------------------------------------------------------------------
  uint64_t calculate_fee_from_weight(uint64_t base_fee, uint64_t weight, uint64_t fee_multiplier, uint64_t fee_quantization_mask)
  {
    uint64_t fee = weight * base_fee * fee_multiplier;
    fee = (fee + fee_quantization_mask - 1) / fee_quantization_mask * fee_quantization_mask;
    return fee;
  }

  //----------------------------------------------------------------------------------------------------
  uint64_t estimate_fee(int n_inputs, int mixin, int n_outputs, size_t extra_size, uint64_t base_fee, uint64_t fee_multiplier, uint64_t fee_quantization_mask)
  {
    const size_t estimated_tx_weight = estimate_tx_weight(n_inputs, mixin, n_outputs, extra_size);
    return calculate_fee_from_weight(base_fee, estimated_tx_weight, fee_multiplier, fee_quantization_mask);
  }

  //----------------------------------------------------------------------------------------------------
  std::pair<size_t, uint64_t> estimate_tx_size_and_weight(int n_inputs, int n_outputs, size_t extra_size)
  {
    THROW_WALLET_EXCEPTION_IF(n_inputs <= 0, tools::error::wallet_internal_error, "Invalid n_inputs");
    THROW_WALLET_EXCEPTION_IF(n_outputs < 0, tools::error::wallet_internal_error, "Invalid n_outputs");

    const int ring_size = config::lol::ring_size;
    if (n_outputs == 1)
      n_outputs = 2; // extra dummy output

    const bool bulletproof = true;
    const bool clsag = true;
    size_t size = estimate_tx_size(n_inputs, ring_size - 1, n_outputs, extra_size);
    uint64_t weight = estimate_tx_weight(n_inputs, ring_size - 1, n_outputs, extra_size);
    return std::make_pair(size, weight);
  }

} // fee
} // functional
} // logic
} // wallet
