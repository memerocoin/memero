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

#include "wallet/api/wallet_errors.h"

namespace wallet {
namespace logic {
namespace functional {
namespace fee {

  //----------------------------------------------------------------------------------------------------
  std::pair<size_t, uint64_t> estimate_tx_size_and_weight
  (
   const int n_inputs
   , const int n_outputs
   , const size_t extra_size
   )
  {
    THROW_WALLET_EXCEPTION_IF(n_inputs <= 0, tools::error::wallet_internal_error, "Invalid n_inputs");
    THROW_WALLET_EXCEPTION_IF(n_outputs < 0, tools::error::wallet_internal_error, "Invalid n_outputs");

    const int ring_size = config::lol::ring_size;
    const int n_adjusted_outputs = n_outputs == 1 ? 2 : n_outputs;

    const size_t size = estimate_tx_size(n_inputs, ring_size - 1, n_adjusted_outputs, extra_size);
    const uint64_t weight = estimate_tx_weight(n_inputs, ring_size - 1, n_adjusted_outputs, extra_size);
    return std::make_pair(size, weight);
  }

} // fee
} // functional
} // logic
} // wallet
