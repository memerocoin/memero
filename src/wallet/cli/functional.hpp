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

#include "wallet/api/wallet2.h"

namespace wallet {
namespace functional {

const std::map<std::string, tools::wallet2::RefreshType> refresh_type_names =
{
  { "full", tools::wallet2::RefreshFull },
  { "optimize-coinbase", tools::wallet2::RefreshOptimizeCoinbase },
  { "optimized-coinbase", tools::wallet2::RefreshOptimizeCoinbase },
  { "no-coinbase", tools::wallet2::RefreshNoCoinbase },
  { "default", tools::wallet2::RefreshDefault },
};

std::optional<tools::wallet2::RefreshType> parse_refresh_type(const std::string s);

std::string get_refresh_type_name(const tools::wallet2::RefreshType type);

constexpr std::array<std::string_view, 5> allowed_priority_strings =
  {{"default", "unimportant", "normal", "elevated", "priority"}};

constexpr std::optional<uint32_t> parse_priority(const std::string_view arg)
{
  const auto priority_pos = std::find(
                                      allowed_priority_strings.begin(),
                                      allowed_priority_strings.end(),
                                      arg);

  if(priority_pos != allowed_priority_strings.end()) {
    return std::distance(allowed_priority_strings.begin(), priority_pos);
  }
  return {};
}


std::string join_priority_strings(const std::string_view delimiter);

std::optional<bool> parse_bool(const std::string s);

}
}
