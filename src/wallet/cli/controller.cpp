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
#include "functional.hpp"

#include "wallet/common/controller.hpp"

#include "tools/common/command_line.h"
#include "tools/common/util.h"

#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <boost/program_options.hpp>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.cli.controller"

namespace wallet {
namespace cli {
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

    boost::trim(buf);

    return buf;
  }

  epee::wipeable_string input_secure_line(const char *prompt)
  {
    PAUSE_READLINE();
    auto pwd_container = tools::password_container::prompt(false, prompt, false);
    if (!pwd_container)
    {
      LOG_ERROR("Failed to read secure line");
      return "";
    }

    epee::wipeable_string buf = pwd_container->password();

    boost::trim(buf);
    return buf;
  }

  std::optional<tools::password_container> default_password_prompter(bool verify)
  {
    return ::wallet::common::controller::password_prompter(verify ? ("Enter a new password for the wallet") : ("Wallet password"), verify);
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

  void parse_bool_and_use(const std::string s, const std::function<void(const bool)> func)
  {
    std::optional<bool> r = wallet::functional::parse_bool(s);
    if (r.has_value())
    {
      func(*r);
    }
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


  void handle_transfer_exception(const std::exception_ptr &e)
  {
    bool warn_of_possible_attack = false;
    try
    {
      std::rethrow_exception(e);
    }
    catch (const tools::error::no_connection_to_daemon&)
    {
      fail_msg_writer() << ("no connection to daemon. Please make sure daemon is running.");
    }
    catch (const tools::error::daemon_busy&)
    {
      fail_msg_writer() << ("daemon is busy. Please try again later.");
    }
    catch (const tools::error::wallet_rpc_error& e)
    {
      LOG_ERROR("RPC error: " << e.to_string());
      fail_msg_writer() << ("RPC error: ") << e.what();
    }
    catch (const tools::error::get_outs_error &e)
    {
      fail_msg_writer() << ("failed to get random outputs to mix: ") << e.what();
    }
    catch (const tools::error::not_enough_unlocked_money& e)
    {
      LOG_PRINT_L0(boost::format("not enough money to transfer, available only %s, sent amount %s") %
        cryptonote::print_money(e.available()) %
        cryptonote::print_money(e.tx_amount()));
      fail_msg_writer() << ("Not enough money in unlocked balance");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::not_enough_money& e)
    {
      LOG_PRINT_L0(boost::format("not enough money to transfer, available only %s, sent amount %s") %
        cryptonote::print_money(e.available()) %
        cryptonote::print_money(e.tx_amount()));
      fail_msg_writer() << ("Not enough money in unlocked balance");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::tx_not_possible& e)
    {
      LOG_PRINT_L0(boost::format("not enough money to transfer, available only %s, transaction amount %s = %s + %s (fee)") %
        cryptonote::print_money(e.available()) %
        cryptonote::print_money(e.tx_amount() + e.fee())  %
        cryptonote::print_money(e.tx_amount()) %
        cryptonote::print_money(e.fee()));
      fail_msg_writer() << ("Failed to find a way to create transactions. This is usually due to dust which is so small it cannot pay for itself in fees, or trying to send more money than the unlocked balance, or not leaving enough for fees");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::not_enough_outs_to_mix& e)
    {
      auto writer = fail_msg_writer();
      writer << ("not enough outputs for specified ring size") << " = " << (e.mixin_count() + 1) << ":";
      for (std::pair<uint64_t, uint64_t> outs_for_amount : e.scanty_outs())
      {
        writer << "\n" << ("output amount") << " = " << cryptonote::print_money(outs_for_amount.first) << ", " << ("found outputs to use") << " = " << outs_for_amount.second;
      }
      writer << ("Please use sweep_unmixable.");
    }
    catch (const tools::error::tx_not_constructed&)
    {
      fail_msg_writer() << ("transaction was not constructed");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::tx_rejected& e)
    {
      fail_msg_writer() << (boost::format(("transaction %s was rejected by daemon")) % get_transaction_hash(e.tx()));
      std::string reason = e.reason();
      if (!reason.empty())
        fail_msg_writer() << ("Reason: ") << reason;
    }
    catch (const tools::error::tx_sum_overflow& e)
    {
      fail_msg_writer() << e.what();
      warn_of_possible_attack = false;
    }
    catch (const tools::error::zero_destination&)
    {
      fail_msg_writer() << ("one of destinations is zero");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::tx_too_big& e)
    {
      fail_msg_writer() << ("failed to find a suitable way to split transactions");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::transfer_error& e)
    {
      LOG_ERROR("unknown transfer error: " << e.to_string());
      fail_msg_writer() << ("unknown transfer error: ") << e.what();
    }
    catch (const tools::error::wallet_internal_error& e)
    {
      LOG_ERROR("internal error: " << e.to_string());
      fail_msg_writer() << ("internal error: ") << e.what();
    }
    catch (const std::exception& e)
    {
      LOG_ERROR("unexpected error: " << e.what());
      fail_msg_writer() << ("unexpected error: ") << e.what();
    }

    if (warn_of_possible_attack)
      fail_msg_writer() << ("There was an error, which could mean the node may be trying to get you to retry creating a transaction, and zero in on which outputs you own. Or it could be a bona fide error. It may be prudent to disconnect from this node, and not try to send a transaction immediately. Alternatively, connect to another node so the original node cannot correlate information.");
  }

  void print_secret_key(const crypto::secret_key &k)
  {
    static constexpr const char hex[] = "0123456789abcdef";
    const uint8_t *ptr = (const uint8_t*)k.data;
    for (size_t i = 0, sz = sizeof(k); i < sz; ++i)
    {
      putchar(hex[*ptr >> 4]);
      putchar(hex[*ptr & 15]);
      ++ptr;
    }
  }
}
}
}
