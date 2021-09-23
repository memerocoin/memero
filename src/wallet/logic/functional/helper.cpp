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


#include "helper.hpp"

#include <sstream>

namespace wallet {
namespace logic {
namespace functional {
namespace helper {

  std::string strjoin(const std::span<const size_t> V, const std::string sep)
  {
    std::stringstream ss;
    bool first = true;
    for (const auto &v: V)
      {
        if (!first)
          ss << sep;
        ss << std::to_string(v);
        first = false;
      }
    return ss.str();
 }

crypto::chacha_key generate_chacha_key(const cryptonote::account_keys &keys, const uint64_t kdf_rounds) {
  crypto::chacha_key key;
  const crypto::secret_key &view_key = keys.m_view_secret_key;
  const crypto::secret_key &spend_key_base = keys.m_spend_secret_key;
  std::array<char, sizeof(view_key) + sizeof(spend_key_base) + 1> data;
  memcpy(data.data(), &view_key, sizeof(view_key));
  memcpy(data.data() + sizeof(view_key), &spend_key_base, sizeof(spend_key_base));
  data[sizeof(data) - 1] = config::HASH_KEY_WALLET;
  crypto::generate_chacha_key(data.data(), sizeof(data), key, kdf_rounds);
  return key;
}


} // helper
} // functional
} // logic
} // wallet
