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

#include "controller.hpp"

#include "tools/common/command_line.h"
#include "tools/common/util.h"

#include <boost/algorithm/string.hpp>

namespace wallet {
namespace controller {

  std::string input_line(const std::string& prompt, bool yesno)
  {
    PAUSE_READLINE();
    std::cout << prompt;
    if (yesno)
      std::cout << "  (Y/N)";
    std::cout << ": " << std::flush;

    std::string buf;
    std::getline(std::cin, buf);

    return epee::string_tools::trim(buf);
  }

  epee::wipeable_string input_secure_line(const char *prompt)
  {
    PAUSE_READLINE();
    auto pwd_container = tools::password_container::prompt(false, prompt, false);
    if (!pwd_container)
    {
      MERROR("Failed to read secure line");
      return "";
    }

    epee::wipeable_string buf = pwd_container->password();

    buf.trim();
    return buf;
  }

  std::optional<tools::password_container> password_prompter(const char *prompt, bool verify)
  {
    PAUSE_READLINE();
    auto pwd_container = tools::password_container::prompt(verify, prompt);
    if (!pwd_container)
    {
      tools::fail_msg_writer() << ("failed to read wallet password");
    }
    return pwd_container;
  }

  std::optional<tools::password_container> default_password_prompter(bool verify)
  {
    return password_prompter(verify ? ("Enter a new password for the wallet") : ("Wallet password"), verify);
  }

  std::string interpret_rpc_response(bool ok, const std::string& status)
  {
    std::string err;
    if (ok)
    {
      if (status == CORE_RPC_STATUS_BUSY)
      {
        err = ("daemon is busy. Please try again later.");
      }
      else if (status != CORE_RPC_STATUS_OK)
      {
        err = status;
      }
    }
    else
    {
      err = ("possibly lost connection to daemon");
    }
    return err;
  }

  tools::scoped_message_writer success_msg_writer(bool color)
  {
    return tools::scoped_message_writer(color ? epee::console_color_green : epee::console_color_default, false, std::string(), el::Level::Info);
  }

  tools::scoped_message_writer message_writer(epee::console_colors color, bool bright)
  {
    return tools::scoped_message_writer(color, bright);
  }

  tools::scoped_message_writer fail_msg_writer()
  {
    return tools::scoped_message_writer(epee::console_color_red, true, ("Error: "), el::Level::Error);
  }

  bool parse_bool(const std::string& s, bool& result)
  {
    if (s == "1" || command_line::is_yes(s))
    {
      result = true;
      return true;
    }
    if (s == "0" || command_line::is_no(s))
    {
      result = false;
      return true;
    }

    boost::algorithm::is_iequal ignore_case{};
    if (boost::algorithm::equals("true", s, ignore_case) || boost::algorithm::equals(("true"), s, ignore_case))
    {
      result = true;
      return true;
    }
    if (boost::algorithm::equals("false", s, ignore_case) || boost::algorithm::equals(("false"), s, ignore_case))
    {
      result = false;
      return true;
    }

    return false;
  }

  std::string get_version_string(uint32_t version)
  {
    return boost::lexical_cast<std::string>(version >> 16) + "." + boost::lexical_cast<std::string>(version & 0xffff);
  }

  bool parse_subaddress_indices(const std::string& arg, std::set<uint32_t>& subaddr_indices)
  {
    subaddr_indices.clear();

    if (arg.substr(0, 6) != "index=")
      return false;
    std::string subaddr_indices_str_unsplit = arg.substr(6, arg.size() - 6);
    std::vector<std::string> subaddr_indices_str;
    boost::split(subaddr_indices_str, subaddr_indices_str_unsplit, boost::is_any_of(","));

    for (const auto& subaddr_index_str : subaddr_indices_str)
    {
      uint32_t subaddr_index;
      if(!epee::string_tools::get_xtype_from_string(subaddr_index, subaddr_index_str))
      {
        fail_msg_writer() << ("failed to parse index: ") << subaddr_index_str;
        subaddr_indices.clear();
        return false;
      }
      subaddr_indices.insert(subaddr_index);
    }
    return true;
  }

  std::optional<std::pair<uint32_t, uint32_t>> parse_subaddress_lookahead(const std::string& str)
  {
    auto r = tools::parse_subaddress_lookahead(str);
    if (!r)
      fail_msg_writer() << ("invalid format for subaddress lookahead; must be <major>:<minor>");
    return r;
  }


}
}
