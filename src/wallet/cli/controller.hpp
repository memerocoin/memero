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
#include "tools/common/scoped_message_writer.h"

namespace wallet {
namespace controller {

  std::string input_line(const std::string& prompt, bool yesno = false);
  epee::wipeable_string input_secure_line(const char *prompt);
  std::optional<tools::password_container> password_prompter(const char *prompt, bool verify);
  std::optional<tools::password_container> default_password_prompter(bool verify);
  std::string interpret_rpc_response(bool ok, const std::string& status);
  tools::scoped_message_writer success_msg_writer(bool color = false);
  tools::scoped_message_writer message_writer(epee::console_colors color = epee::console_color_default, bool bright = false);
  tools::scoped_message_writer fail_msg_writer();
  void parse_bool_and_use(const std::string s, const std::function<void(const bool)> func);

  std::string get_version_string(uint32_t version);

  bool parse_subaddress_indices(const std::string& arg, std::set<uint32_t>& subaddr_indices);
  std::optional<std::pair<uint32_t, uint32_t>> parse_subaddress_lookahead(const std::string& str);

  void handle_transfer_exception(const std::exception_ptr &e);

  void print_secret_key(const crypto::secret_key &k);
}
}
