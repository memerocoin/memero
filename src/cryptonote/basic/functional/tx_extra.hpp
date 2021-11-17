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

#include "../type/string_blob_type.hpp"
#include "../cryptonote_basic.h"
#include "../type/tx_extra.hpp"
#include "../type/subaddress_index.hpp"

#include "tools/epee/include/blob.hpp"

namespace cryptonote
{
  std::optional<std::vector<tx_extra_field>> parse_tx_extra(const epee::blob::span tx_extra);

  std::optional<crypto::public_key> get_tx_pub_key_from_extra(const epee::blob::span tx_extra);
  std::optional<crypto::public_key> get_tx_pub_key_from_extra(const transaction_prefix& tx);
  std::optional<crypto::public_key> get_tx_pub_key_from_extra(const transaction& tx);

  std::optional<std::vector<crypto::public_key>> get_all_tx_output_public_keys_from_extra
  (
   const transaction& tx
   , const size_t output_count
   );

  std::optional<std::vector<crypto::public_key>>
  get_tx_output_public_keys_from_extra(const epee::blob::span tx_extra);

  std::optional<std::vector<crypto::public_key>>
  get_tx_output_public_keys_from_extra(const transaction_prefix& tx);
}
