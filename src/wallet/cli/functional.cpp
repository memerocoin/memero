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

#include "functional.hpp"

#include "tools/common/command_line.h"

namespace wallet {
namespace functional {

std::string join_priority_strings(const std::string_view delimiter)
{
  return std::accumulate(
                         std::next(allowed_priority_strings.begin()),
                         allowed_priority_strings.end(),
                         std::string(allowed_priority_strings[0]),
                         [delimiter](const std::string x, const std::string_view y) -> std::string {
                           return x + std::string(delimiter) + std::string(y);
                         }
                         );
}

std::optional<bool> parse_bool(const std::string s)
{
  if (s == "1" || command_line::is_yes(s))
  {
    return true;
  }
  if (s == "0" || command_line::is_no(s))
  {
    return false;
  }

  boost::algorithm::is_iequal ignore_case{};

  if (boost::algorithm::equals("true", s, ignore_case) || boost::algorithm::equals(("true"), s, ignore_case))
  {
    return true;
  }
  if (boost::algorithm::equals("false", s, ignore_case) || boost::algorithm::equals(("false"), s, ignore_case))
  {
    return false;
  }

  return {};
}


}
}
