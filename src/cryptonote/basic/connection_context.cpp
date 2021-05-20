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

#include "connection_context.h"

namespace cryptonote
{

  bool cryptonote_connection_context::handshake_complete() const noexcept { return m_state != state_before_handshake; }

  void cryptonote_connection_context::set_max_bytes(const int command, const size_t bytes) {
    const auto i = std::lower_bound(m_max_bytes.begin(), m_max_bytes.end(), std::make_pair(command, bytes), [](const std::pair<int, size_t> &e0, const std::pair<int, size_t> &e1){
      return e0.first < e1.first;
    });
    if (i == m_max_bytes.end())
      m_max_bytes.push_back(std::make_pair(command, bytes));
    else if (i->first == command)
      i->second = bytes;
    else
      m_max_bytes.insert(i, std::make_pair(command, bytes));
  }

  size_t cryptonote_connection_context::get_max_bytes(const int command) const {
    const auto i = std::lower_bound(m_max_bytes.begin(), m_max_bytes.end(), std::make_pair(command, 0), [](const std::pair<int, size_t> &e0, const std::pair<int, size_t> &e1){
      return e0.first < e1.first;
    });
    if (i == m_max_bytes.end() || i->first != command)
      return std::numeric_limits<size_t>::max();
    else
      return i->second;
  }

  std::string get_protocol_state_string(const cryptonote_connection_context::state s)
  {
    switch (s)
    {
    case cryptonote_connection_context::state_before_handshake:
      return "before_handshake";
    case cryptonote_connection_context::state_synchronizing:
      return "synchronizing";
    case cryptonote_connection_context::state_standby:
      return "standby";
    case cryptonote_connection_context::state_idle:
      return "idle";
    case cryptonote_connection_context::state_normal:
      return "normal";
    default:
      return "unknown";
    }
  }

  char get_protocol_state_char(const cryptonote_connection_context::state s)
  {
    switch (s)
    {
    case cryptonote_connection_context::state_before_handshake:
      return 'h';
    case cryptonote_connection_context::state_synchronizing:
      return 's';
    case cryptonote_connection_context::state_standby:
      return 'w';
    case cryptonote_connection_context::state_idle:
      return 'i';
    case cryptonote_connection_context::state_normal:
      return 'n';
    default:
      return 'u';
    }
  }

}
