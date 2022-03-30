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

/*!
 * \file simplewallet.cpp
 *
 * \brief Source file that defines simple_wallet class.
 */

#include "simplewallet.h"
#include "string.hpp"
#include "functional.hpp"
#include "controller.hpp"

#include "wallet/logic/functional/fee.hpp"
#include "wallet/logic/functional/wallet.hpp"
#include "wallet/logic/controller/wallet.hpp"

#include "wallet/common/wallet_args.h"
#include "wallet/common/controller.hpp"
#include "wallet/mnemonics/electrum-words.h"

#include "daemon/cli/daemon_common.hpp"

#include "tools/common/scoped_message_writer.h"

#include "cryptonote/protocol/cryptonote_protocol_handler.h"

#include "math/consensus/consensus.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <boost/range/adaptor/transformed.hpp>



namespace cryptonote
{

using namespace wallet::usage;
using namespace wallet::cli::controller;
using namespace wallet::common::controller;
using namespace wallet::arg;

namespace po = boost::program_options;
typedef cryptonote::simple_wallet sw;

void PRINT_USAGE(const std::string usage_help) {
  fail_msg_writer() << boost::format("usage: %s") % usage_help;
}

enum TransferType {
  Transfer,
  TransferLocked,
};

std::string simple_wallet::get_commands_str()
{
  std::stringstream ss;
  ss << ("Commands: ") << std::endl;
  std::string usage = m_cmd_binder.get_usage();
  boost::replace_all(usage, "\n", "\n  ");
  usage.insert(0, "  ");
  ss << usage << std::endl;
  return ss.str();
}

std::string simple_wallet::get_command_usage(const std::vector<std::string> &args)
{
  std::pair<std::string, std::string> documentation = m_cmd_binder.get_documentation(args);
  std::stringstream ss;
  if(documentation.first.empty())
  {
    ss << ("Unknown command: ") << args.front();
  }
  else
  {
    std::string usage = documentation.second.empty() ? args.front() : documentation.first;
    std::string description = documentation.second.empty() ? documentation.first : documentation.second;
    usage.insert(0, "  ");
    ss << ("Command usage: ") << std::endl << usage << std::endl << std::endl;
    boost::replace_all(description, "\n", "\n  ");
    description.insert(0, "  ");
    ss << ("Command description: ") << std::endl << description << std::endl;
  }
  return ss.str();
}

bool simple_wallet::viewkey(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  // don't log
  std::cout << "secret: " << m_wallet->get_account().get_keys().m_view_secret_key << std::endl;
  std::cout << "public: " << m_wallet->get_account().get_keys().m_account_address.m_view_public_key << std::endl;

  return true;
}

bool simple_wallet::spendkey(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  // don't log
  std::cout << "secret: " << m_wallet->get_account().get_keys().m_spend_secret_key << std::endl;
  std::cout << "public: " << m_wallet->get_account().get_keys().m_account_address.m_spend_public_key << std::endl;

  return true;
}

bool simple_wallet::print_seed()
{
  bool success =  false;
  epee::wipeable_string seed;

  epee::wipeable_string seed_pass;
  success = m_wallet->get_seed(seed, seed_pass);

  if (success)
  {
    print_seed(seed);
  }
  else
  {
    fail_msg_writer() << ("Failed to retrieve seed");
  }
  return true;
}

bool simple_wallet::seed(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  return print_seed();
}

bool simple_wallet::change_password(const std::vector<std::string> &args)
{
  const auto orig_pwd_container = get_and_verify_password();

  if(orig_pwd_container == std::nullopt)
  {
    fail_msg_writer() << ("Your original password was incorrect.");
    return true;
  }

  // prompts for a new password, pass true to verify the password
  const auto pwd_container = default_password_prompter(true);
  if(!pwd_container)
    return true;

  try
  {
    m_wallet->change_password(m_wallet_file, orig_pwd_container->password(), pwd_container->password());
  }
  catch (const tools::error::wallet_logic_error& e)
  {
    fail_msg_writer() << ("Error with wallet rewrite: ") + std::string(e.what());
    return true;
  }

  return true;
}

bool simple_wallet::version(const std::vector<std::string> &args)
{
  daemon_common::show_version();
  return true;
}

bool simple_wallet::on_unknown_command(const std::vector<std::string> &args)
{
  if (args[0] == "exit" || args[0] == "q") // backward compat
    return false;
  fail_msg_writer() << boost::format(tr("Unknown command '%s', try 'help'")) % args.front();
  return true;
}

bool simple_wallet::on_empty_command()
{
  return true;
}

bool simple_wallet::on_cancelled_command()
{
  return true;
}

bool simple_wallet::set_always_confirm_transfers(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    parse_bool_and_use(args[1], [&](bool r) {
      m_wallet->always_confirm_transfers(r);
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    });
  }
  return true;
}

bool simple_wallet::set_store_tx_info(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    parse_bool_and_use(args[1], [&](bool r) {
      m_wallet->store_tx_info(r);
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    });
  }
  return true;
}

bool simple_wallet::set_default_priority(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  uint32_t priority = 0;
  try
  {
    if (strchr(args[1].c_str(), '-'))
    {
      fail_msg_writer() << ("priority must be either 0, 1, 2, 3, or 4, or one of: ") <<
        wallet::functional::join_priority_strings(", ");
      return true;
    }
    if (args[1] == "0")
    {
      priority = 0;
    }
    else
    {
      bool found = false;
      for (size_t n = 0; n < wallet::functional::allowed_priority_strings.size(); ++n)
      {
        if (wallet::functional::allowed_priority_strings[n] == args[1])
        {
          found = true;
          priority = n;
        }
      }
      if (!found)
      {
        priority = boost::lexical_cast<int>(args[1]);
        if (priority < 1 || priority > 4)
        {
          fail_msg_writer() << ("priority must be either 0, 1, 2, 3, or 4, or one of: ") << wallet::functional::join_priority_strings(", ");
          return true;
        }
      }
    }

    const auto pwd_container = get_and_verify_password();
    if (pwd_container)
    {
      m_wallet->set_default_priority(priority);
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    }
    return true;
  }
  catch(const boost::bad_lexical_cast &)
  {
    fail_msg_writer() << ("priority must be either 0, 1, 2, 3, or 4, or one of: ") << wallet::functional::join_priority_strings(", ");
    return true;
  }
  catch(...)
  {
    fail_msg_writer() << ("could not change default priority");
    return true;
  }
}

bool simple_wallet::set_unit(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const std::string &unit = args[1];
  unsigned int decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT;

  if (unit == "lolnero")
    decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT;
  else if (unit == "millinero")
    decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT - 3;
  else if (unit == "micronero")
    decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT - 6;
  else if (unit == "nanonero")
    decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT - 9;
  else if (unit == "piconero")
    decimal_point = 0;
  else
  {
    fail_msg_writer() << ("invalid unit");
    return true;
  }

  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    cryptonote::set_default_decimal_point(decimal_point);
    m_wallet->rewrite(m_wallet_file, pwd_container->password());
  }
  return true;
}

bool simple_wallet::set_merge_destinations(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    parse_bool_and_use(args[1], [&](bool r) {
      m_wallet->merge_destinations(r);
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    });
  }
  return true;
}

bool simple_wallet::set_confirm_export_overwrite(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    parse_bool_and_use(args[1], [&](bool r) {
      m_wallet->confirm_export_overwrite(r);
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    });
  }
  return true;
}

bool simple_wallet::set_refresh_from_block_height(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    uint64_t height;
    if (!epee::string_tools::get_xtype_from_string(height, args[1]))
    {
      fail_msg_writer() << ("Invalid height");
      return true;
    }
    m_wallet->set_refresh_from_block_height(height);
    m_wallet->rewrite(m_wallet_file, pwd_container->password());
  }
  return true;
}

bool simple_wallet::set_subaddress_lookahead(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    auto lookahead = parse_subaddress_lookahead(args[1]);
    if (lookahead)
    {
      m_wallet->set_subaddress_lookahead(lookahead->first, lookahead->second);
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    }
  }
  return true;
}

bool simple_wallet::set_ignore_fractional_outputs(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    parse_bool_and_use(args[1], [&](bool r) {
      m_wallet->ignore_fractional_outputs(r);
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    });
  }
  return true;
}


bool simple_wallet::help(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  if(args.empty())
  {
    message_writer() << "";
    message_writer() << "account                     - Show account.";
    message_writer() << "address                     - Show address.";
    message_writer() << "refresh                     - Synchronize wallet with the Lolnero network.";
    message_writer() << "transfer <address> <amount> - Send LOL to an address.";
    message_writer() << "exit                        - Exit wallet.";
    message_writer() << "";
    message_writer() << "help <command>              - Show a command's documentation.";
    message_writer() << "help all                    - Show the list of all available commands.";
    message_writer() << "";
  }
  else if ((args.size() == 1) && (args.front() == "all"))
  {
    success_msg_writer() << get_commands_str();
  }
  else
  {
    success_msg_writer() << get_command_usage(args);
  }
  return true;
}

simple_wallet::simple_wallet()
  : 
  m_current_subaddress_account(0)
  , m_in_command(false)
{
  m_cmd_binder.set_handler("start-mining",
                           std::bind(&simple_wallet::on_command, this, &simple_wallet::start_mining, std::placeholders::_1),
                           (USAGE_START_MINING),
                           ("Start mining in the daemon."));
  m_cmd_binder.set_handler("stop-mining",
                           std::bind(&simple_wallet::on_command, this, &simple_wallet::stop_mining, std::placeholders::_1),
                           ("Stop mining in the daemon."));
  m_cmd_binder.set_handler("refresh",
                           std::bind(&simple_wallet::on_command, this, &simple_wallet::refresh, std::placeholders::_1),
                           ("Synchronize the transactions and balance."));
  m_cmd_binder.set_handler("balance",
                           std::bind(&simple_wallet::on_command, this, &simple_wallet::show_balance, std::placeholders::_1),
                           (USAGE_SHOW_BALANCE),
                           ("Show the wallet's balance of the currently selected account."));
  m_cmd_binder.set_handler("in",
                           std::bind(&simple_wallet::on_command, this, &simple_wallet::show_incoming,std::placeholders::_1),
                           (USAGE_INCOMING),
                           std::string(wallet::help::incoming));
  m_cmd_binder.set_handler("transfer", std::bind(&simple_wallet::on_command, this, &simple_wallet::transfer, std::placeholders::_1),
                           (USAGE_TRANSFER),
                           std::string(wallet::help::transfer));
  m_cmd_binder.set_handler("account",
                           std::bind(&simple_wallet::on_command, this, &simple_wallet::account, std::placeholders::_1),
                           (USAGE_ACCOUNT),
                           std::string(wallet::help::account));
  m_cmd_binder.set_handler("address",
                           std::bind(&simple_wallet::on_command, this, &simple_wallet::print_address, std::placeholders::_1),
                           (USAGE_ADDRESS),
                           std::string(wallet::help::address));
  m_cmd_binder.set_handler("view-key",
                           std::bind(&simple_wallet::on_command, this, &simple_wallet::viewkey, std::placeholders::_1),
                           ("Display the private view key."));
  m_cmd_binder.set_handler("spend-key",
                           std::bind(&simple_wallet::on_command, this, &simple_wallet::spendkey, std::placeholders::_1),
                           ("Display the private spend key."));
  m_cmd_binder.set_handler("seed",
                           std::bind(&simple_wallet::on_command, this, &simple_wallet::seed, std::placeholders::_1),
                           ("Display the Electrum-style mnemonic seed"));
  m_cmd_binder.set_handler("set",
                           std::bind(&simple_wallet::on_command, this, &simple_wallet::set_variable, std::placeholders::_1),
                           (USAGE_SET_VARIABLE),
                           std::string(wallet::help::set_variable));
  m_cmd_binder.set_handler("show",
                           std::bind(&simple_wallet::on_command, this, &simple_wallet::show, std::placeholders::_1),
                           (USAGE_SHOW),
                           std::string(wallet::help::show));
  m_cmd_binder.set_handler("rescan",
                           std::bind(&simple_wallet::on_command, this, &simple_wallet::rescan_blockchain, std::placeholders::_1),
                           (USAGE_RESCAN),
                           ("Rescan the blockchain from scratch. If \"hard\" is specified, you will lose any information which can not be recovered from the blockchain itself."));
  m_cmd_binder.set_handler("status",
                           std::bind(&simple_wallet::on_command, this, &simple_wallet::status, std::placeholders::_1),
                           ("Show the wallet's status."));
  m_cmd_binder.set_handler("tx",
                           std::bind(&simple_wallet::on_command, this, &simple_wallet::show_tx, std::placeholders::_1),
                           (USAGE_SHOW_TX),
                           ("Show information about a transactionto/from this address."));
  m_cmd_binder.set_handler("password",
                           std::bind(&simple_wallet::on_command, this, &simple_wallet::change_password, std::placeholders::_1),
                           ("Change the wallet's password."));
  m_cmd_binder.set_handler("version",
                           std::bind(&simple_wallet::on_command, this, &simple_wallet::version, std::placeholders::_1),
                           (USAGE_VERSION),
                           ("Returns version information"));
  m_cmd_binder.set_handler("help",
                           std::bind(&simple_wallet::on_command, this, &simple_wallet::help, std::placeholders::_1),
                           (USAGE_HELP),
                           ("Show the help section or the documentation about a <command>."));
  m_cmd_binder.set_unknown_command_handler(std::bind(&simple_wallet::on_command, this, &simple_wallet::on_unknown_command, std::placeholders::_1));
  m_cmd_binder.set_empty_command_handler(std::bind(&simple_wallet::on_empty_command, this));
  m_cmd_binder.set_cancel_handler(std::bind(&simple_wallet::on_cancelled_command, this));
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::set_variable(const std::vector<std::string> &args)
{
  if (args.empty())
  {
    std::string seed_language = m_wallet->get_seed_language();
    std::string priority_string = "invalid";
    uint32_t priority = m_wallet->get_default_priority();
    if (priority < wallet::functional::allowed_priority_strings.size())
      priority_string = wallet::functional::allowed_priority_strings[priority];
    success_msg_writer() << "always-confirm-transfers = " << m_wallet->always_confirm_transfers();
    success_msg_writer() << "store-tx-info = " << m_wallet->store_tx_info();
    success_msg_writer() << "priority = " << priority<< " (" << priority_string << ")";
    success_msg_writer() << "unit = " << cryptonote::get_unit(cryptonote::get_default_decimal_point());
    success_msg_writer() << "merge-destinations = " << m_wallet->merge_destinations();
    success_msg_writer() << "confirm-export-overwrite = " << m_wallet->confirm_export_overwrite();
    success_msg_writer() << "refresh-from-block-height = " << m_wallet->get_refresh_from_block_height();
    const std::pair<size_t, size_t> lookahead = m_wallet->get_subaddress_lookahead();
    success_msg_writer() << "subaddress-lookahead = " << lookahead.first << ":" << lookahead.second;
    success_msg_writer() << "ignore-fractional-outputs = " << m_wallet->ignore_fractional_outputs();
    return true;
  }
  else
  {

#define CHECK_SIMPLE_VARIABLE(name, f, help) do \
  if (args[0] == name) { \
    if (args.size() <= 1) \
    { \
      fail_msg_writer() << "set " << #name << ": " << ("needs an argument") << " (" << help << ")"; \
      return true; \
    } \
    else \
    { \
      f(args); \
      return true; \
    } \
  } while(0)

    CHECK_SIMPLE_VARIABLE("always-confirm-transfers", set_always_confirm_transfers, ("0 or 1"));
    CHECK_SIMPLE_VARIABLE("store-tx-info", set_store_tx_info, ("0 or 1"));
    CHECK_SIMPLE_VARIABLE("priority", set_default_priority, ("0, 1, 2, 3, or 4, or one of ") << wallet::functional::join_priority_strings(", "));
    CHECK_SIMPLE_VARIABLE("unit", set_unit, ("lolnero, millinero, micronero, nanonero, piconero"));
    CHECK_SIMPLE_VARIABLE("merge-destinations", set_merge_destinations, ("0 or 1"));
    CHECK_SIMPLE_VARIABLE("confirm-export-overwrite", set_confirm_export_overwrite, ("0 or 1"));
    CHECK_SIMPLE_VARIABLE("refresh-from-block-height", set_refresh_from_block_height, ("block height"));
    CHECK_SIMPLE_VARIABLE
      ("subaddress-lookahead", set_subaddress_lookahead, ("<account>:<subaddress>"));
    CHECK_SIMPLE_VARIABLE("ignore-fractional-outputs", set_ignore_fractional_outputs, ("0 or 1"));
  }
  fail_msg_writer() << ("set: unrecognized argument(s)");
  return true;
}

//----------------------------------------------------------------------------------------------------
bool simple_wallet::ask_wallet_create_if_needed()
{
  LOG_PRINT_L3("simple_wallet::ask_wallet_create_if_needed() started");
  std::string wallet_path;
  std::string confirm_creation;
  bool wallet_name_valid = false;
  bool keys_file_exists;
  bool wallet_file_exists;

  do{
      LOG_PRINT_L3("User asked to specify wallet file name.");
      wallet_path = input_line(
        (m_restoring ? "Specify a new wallet file name for your restored wallet (e.g., MyWallet).\n"
        "Wallet file name (or Ctrl-C to quit)" :
        "Specify wallet file name (e.g., MyWallet). If the wallet doesn't exist, it will be created.\n"
        "Wallet file name (or Ctrl-C to quit)")
      );
      if(std::cin.eof())
      {
        LOG_ERROR("Unexpected std::cin.eof() - Exited simple_wallet::ask_wallet_create_if_needed()");
        return false;
      }
      if(!tools::wallet2::wallet_valid_path_format(wallet_path))
      {
        fail_msg_writer() << ("Wallet name not valid. Please try again or use Ctrl-C to quit.");
        wallet_name_valid = false;
      }
      else
      {
        tools::wallet2::wallet_exists(wallet_path, keys_file_exists, wallet_file_exists);
        LOG_PRINT_L3("wallet_path: " + wallet_path);
        LOG_PRINT_L3
          (
           "keys_file_exists: "
           + std::to_string(keys_file_exists)
           + "  wallet_file_exists: "
           + std::to_string(wallet_file_exists)
           );

        if((keys_file_exists || wallet_file_exists) && (!m_generate_new.empty() || m_restoring))
        {
          fail_msg_writer() << ("Attempting to generate or restore wallet, but specified file(s) exist.  Exiting to not risk overwriting.");
          return false;
        }
        if(wallet_file_exists && keys_file_exists) //Yes wallet, yes keys
        {
          success_msg_writer() << ("Wallet and key files found, loading...");
          m_wallet_file = wallet_path;
          return true;
        }
        else if(!wallet_file_exists && keys_file_exists) //No wallet, yes keys
        {
          success_msg_writer() << ("Key file found but not wallet file. Regenerating...");
          m_wallet_file = wallet_path;
          return true;
        }
        else if(wallet_file_exists && !keys_file_exists) //Yes wallet, no keys
        {
          fail_msg_writer() << ("Key file not found. Failed to open wallet: ") << "\"" << wallet_path << "\". Exiting.";
          return false;
        }
        else if(!wallet_file_exists && !keys_file_exists) //No wallet, no keys
        {
          success_msg_writer() << ("Generating new wallet...");
          m_generate_new = wallet_path;
          return true;
        }
      }
    } while(!wallet_name_valid);

  LOG_ERROR("Failed out of do-while loop in ask_wallet_create_if_needed()");
  return false;
}

/*!
 * \brief Prints the seed with a nice message
 * \param seed seed to print
 */
void simple_wallet::print_seed(const epee::wipeable_string &seed)
{
  success_msg_writer() <<
    "\n" <<
    "**********************************************************************"
    ;

  // don't log
  int space_index = 0;
  size_t len  = seed.size();
  for (const char *ptr = seed.data(); len--; ++ptr)
  {
    if (*ptr == ' ')
    {
      if (space_index == 15 || space_index == 7)
        putchar('\n');
      else
        putchar(*ptr);
      ++space_index;
    }
    else
      putchar(*ptr);
  }

  fflush(stdout);

  success_msg_writer() <<
    "\n" <<
    "**********************************************************************\n"
    ;
}
//----------------------------------------------------------------------------------------------------
static bool might_be_partial_seed(const epee::wipeable_string &words)
{
  std::vector<epee::wipeable_string> seed;

  boost::split(seed, words, boost::is_any_of("\t "), boost::token_compress_on);
  return seed.size() < 24;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::init(const boost::program_options::variables_map& vm)
{
  epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){
    m_electrum_seed.clear();
  });

  epee::wipeable_string password;

  if (!handle_command_line(vm))
    return false;

  if((!m_generate_new.empty()) + (!m_wallet_file.empty()) + (!m_generate_from_spend_key.empty()) > 1)
  {
    fail_msg_writer() << ("can't specify more than one of --new=\"wallet_name\", --open=\"wallet_name\" and --generate-from-spend-key=\"wallet_name\"");
    return false;
  }
  else if (m_generate_new.empty() && m_wallet_file.empty() && m_generate_from_spend_key.empty())
  {
    if(!ask_wallet_create_if_needed()) return false;
  }

  if (!m_generate_new.empty() || m_restoring)
  {
    if (!m_subaddress_lookahead.empty() && !parse_subaddress_lookahead(m_subaddress_lookahead))
      return false;

    std::string old_language;
    // check for recover flag.  if present, require electrum word list (only recovery option for now).
    if (m_restore_deterministic_wallet)
    {
      if (!m_wallet_file.empty())
      {
        fail_msg_writer() << ("--restore uses --new, not --open");
        return false;
      }

      if (m_electrum_seed.empty())
      {
        {
          m_electrum_seed = "";
          do
          {
            const char *prompt = m_electrum_seed.empty() ? "Specify Electrum seed" : "Electrum seed continued";
            epee::wipeable_string electrum_seed = input_secure_line(prompt);
            if (std::cin.eof())
              return false;
            if (electrum_seed.empty())
            {
              fail_msg_writer() << ("specify a recovery parameter with the --electrum-seed=\"words list here\"");
              return false;
            }
            m_electrum_seed += electrum_seed;
            m_electrum_seed += ' ';
          } while (might_be_partial_seed(m_electrum_seed));
        }
      }

      {
        if (!crypto::ElectrumWords::words_to_bytes(m_electrum_seed, m_recovery_key, old_language))
        {
          fail_msg_writer() << ("Electrum-style word list failed verification");
          return false;
        }
      }
    }
    if (!m_generate_from_spend_key.empty())
    {
      m_wallet_file = m_generate_from_spend_key;
      // parse spend secret key
      epee::wipeable_string spendkey_string = input_secure_line("Secret spend key");
      if (std::cin.eof())
        return false;
      if (spendkey_string.empty()) {
        fail_msg_writer() << ("No data supplied, cancelled");
        return false;
      }
      spendkey_string = epee::string_tools::pod_to_hex((m_recovery_key));

      auto r = new_wallet(vm, m_recovery_key);
      LOG_ERROR_AND_RETURN_UNLESS(r, false, ("account creation failed"));
      password = *r;
    }
    else
    {
      if (m_generate_new.empty()) {
        fail_msg_writer() << ("specify a wallet path with --new (not --open)");
        return false;
      }
      m_wallet_file = m_generate_new;
      std::optional<epee::wipeable_string> r;
      if (m_restore_deterministic_wallet) {
        r = new_wallet(vm, m_recovery_key);
      } else {
        r = new_wallet(vm, {});
      }

      LOG_ERROR_AND_RETURN_UNLESS(r, false, ("account creation failed"));
      password = *r;
    }

    if (m_restoring)
    {
      m_wallet->set_refresh_from_block_height(0);
    }
    m_wallet->rewrite(m_wallet_file, password);
  }
  else
  {
    assert(!m_wallet_file.empty());
    if (!m_subaddress_lookahead.empty())
    {
      fail_msg_writer() << ("can't specify --subaddress-lookahead and --open at the same time");
      return false;
    }
    auto r = open_wallet(vm);
    LOG_ERROR_AND_RETURN_UNLESS(r, false, ("failed to open account"));
    password = *r;
  }
  if (!m_wallet)
  {
    fail_msg_writer() << ("wallet is null");
    return false;
  }

  m_wallet->callback(this);

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::deinit()
{
  if (!m_wallet.get())
    return true;

  return close_wallet();
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::handle_command_line(const boost::program_options::variables_map& vm)
{
  m_wallet_file                   = command_line::get_arg(vm, wallet_args::arg_wallet_file());
  m_generate_new                  = command_line::get_arg(vm, arg_generate_new_wallet);
  m_generate_from_spend_key       = command_line::get_arg(vm, arg_generate_from_spend_key);
  m_electrum_seed                 = command_line::get_arg(vm, arg_electrum_seed);
  m_restore_deterministic_wallet  = command_line::get_arg(vm, arg_restore_deterministic_wallet);
  m_do_not_relay                  = command_line::get_arg(vm, arg_do_not_relay);
  m_subaddress_lookahead          = command_line::get_arg(vm, arg_subaddress_lookahead);
  m_restoring                     = !m_generate_from_spend_key.empty() ||
                                    m_restore_deterministic_wallet;

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::try_connect_to_daemon(bool silent, uint32_t* version)
{
  uint32_t version_ = 0;
  if (!version)
    version = &version_;
  if (!m_wallet->check_connection(version))
  {
    if (!silent)
      fail_msg_writer() << ("wallet failed to connect to daemon: ") << m_wallet->get_daemon_address() << ". " <<
        ("Daemon either is not started or wrong port was passed. "
        "Please make sure daemon is running or change the daemon address using the 'set_daemon' command.");
    return false;
  }
  if (((*version >> 16) != CORE_RPC_VERSION_MAJOR))
  {
    if (!silent)
      fail_msg_writer() << boost::format(tr("Daemon uses a different RPC major version (%u) than the wallet (%u): %s. Either update one of them, or use --allow-mismatched-daemon-version.")) % (*version>>16) % CORE_RPC_VERSION_MAJOR % m_wallet->get_daemon_address();
    return false;
  }
  return true;
}

/*!
 * \brief Gets the word seed language from the user.
 *
 * User is asked to choose from a list of supported languages.
 *
 * \return The chosen language.
 */
std::string simple_wallet::get_mnemonic_language()
{
  std::vector<std::string> language_list_self;
  crypto::ElectrumWords::get_language_list(language_list_self, false);
  return language_list_self[0];
}
//----------------------------------------------------------------------------------------------------
std::optional<tools::password_container> simple_wallet::get_and_verify_password() const
{
  auto pwd_container = default_password_prompter(m_wallet_file.empty());
  if (!pwd_container)
    return std::nullopt;

  if (!m_wallet->verify_password(pwd_container->password()))
  {
    fail_msg_writer() << ("invalid password");
    return std::nullopt;
  }
  return pwd_container;
}
//----------------------------------------------------------------------------------------------------
std::optional<epee::wipeable_string> simple_wallet::new_wallet
(
 const boost::program_options::variables_map& vm
 , const std::optional<crypto::secret_key> recovery_key
 )
{
  std::pair<std::unique_ptr<tools::wallet2>, tools::password_container> rc;
  try { rc = tools::wallet2::make_new(vm, password_prompter); }
  catch(const std::exception &e) { fail_msg_writer() << ("Error creating wallet: ") + std::string(e.what()); return {}; }
  m_wallet = std::move(rc.first);
  if (!m_wallet)
  {
    return {};
  }
  epee::wipeable_string password = rc.second.password();

  if (!m_subaddress_lookahead.empty())
  {
    auto lookahead = parse_subaddress_lookahead(m_subaddress_lookahead);
    assert(lookahead);
    m_wallet->set_subaddress_lookahead(lookahead->first, lookahead->second);
  }

  std::string mnemonic_language;

  std::vector<std::string> language_list;
  crypto::ElectrumWords::get_language_list(language_list);
  if (mnemonic_language.empty() && std::find(language_list.begin(), language_list.end(), m_mnemonic_language) != language_list.end())
  {
    mnemonic_language = m_mnemonic_language;
  }

  // Ask for seed language if:
  // it's a deterministic wallet AND
  // a seed language is not already specified AND
  // (it is not a wallet restore OR if it was a deprecated wallet
  // that was earlier used before this restore)
  if (mnemonic_language.empty() && (!m_restore_deterministic_wallet))
  {
    mnemonic_language = get_mnemonic_language();
    if (mnemonic_language.empty())
      return {};
  }

  m_wallet->set_seed_language(mnemonic_language);

  crypto::secret_key recovery_val;
  try
  {
    recovery_val = m_wallet->generate(m_wallet_file, std::move(rc.second).password(), recovery_key);
    message_writer(epee::console_colors::white, true) << ("Generated new wallet: ")
      << m_wallet->get_account().get_public_address_str(m_wallet->nettype());
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << ("failed to generate new wallet: ") + std::string(e.what());
    return {};
  }

  // convert rng value to electrum-style word list
  epee::wipeable_string electrum_words;

  crypto::ElectrumWords::bytes_to_words(recovery_val, electrum_words, mnemonic_language);

  if (!recovery_key) {
    success_msg_writer(true) <<
      "\n" <<
      boost::format(tr("NOTE: the following %s can be used to recover access to your wallet. "
                      "Write them down and store them somewhere safe and secure. Please do not store them in "
                      "your email or on file storage services outside of your immediate control.")) % ("25 words");

    print_seed(electrum_words);
  } else {
    success_msg_writer();
  }

  success_msg_writer() <<
    "Use the \"help\" command to see a list of available commands.\n"
    ;

  return password;
}
//----------------------------------------------------------------------------------------------------
std::optional<epee::wipeable_string> simple_wallet::new_wallet(const boost::program_options::variables_map& vm)
{
  std::pair<std::unique_ptr<tools::wallet2>, tools::password_container> rc;
  try { rc = tools::wallet2::make_new(vm, password_prompter); }
  catch(const std::exception &e) { fail_msg_writer() << ("Error creating wallet: ") + std::string(e.what()); return {}; }
  m_wallet = std::move(rc.first);
  m_wallet->callback(this);
  if (!m_wallet)
  {
    return {};
  }
  epee::wipeable_string password = rc.second.password();

  if (!m_subaddress_lookahead.empty())
  {
    auto lookahead = parse_subaddress_lookahead(m_subaddress_lookahead);
    assert(lookahead);
    m_wallet->set_subaddress_lookahead(lookahead->first, lookahead->second);
  }

  return password;
}
//----------------------------------------------------------------------------------------------------
std::optional<epee::wipeable_string> simple_wallet::open_wallet(const boost::program_options::variables_map& vm)
{
  if (!tools::wallet2::wallet_valid_path_format(m_wallet_file))
  {
    fail_msg_writer() << ("wallet file path not valid: ") << m_wallet_file;
    return {};
  }

  bool keys_file_exists;
  bool wallet_file_exists;

  tools::wallet2::wallet_exists(m_wallet_file, keys_file_exists, wallet_file_exists);
  if(!keys_file_exists)
  {
    fail_msg_writer() << ("Key file not found. Failed to open wallet");
    return {};
  }

  epee::wipeable_string password;
  try
  {
    auto rc = tools::wallet2::make_from_file(vm, "", password_prompter);
    m_wallet = std::move(rc.first);
    password = std::move(std::move(rc.second).password());
    if (!m_wallet)
    {
      return {};
    }

    m_wallet->callback(this);
    m_wallet->load(m_wallet_file, password);
    std::string prefix;
    prefix = ("Opened wallet");
    message_writer(epee::console_colors::white, true) <<
      prefix << ": " << m_wallet->get_account().get_public_address_str(m_wallet->nettype());
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << ("failed to load wallet: ") + std::string(e.what());
    if (m_wallet)
    {
      // only suggest removing cache if the password was actually correct
      bool password_is_correct = false;
      try
      {
        password_is_correct = m_wallet->verify_password(password);
      }
      catch (...) { } // guard against I/O errors
      if (password_is_correct)
        fail_msg_writer() << boost::format(tr("You may want to remove the file \"%s\" and try again")) % m_wallet_file;
    }
    return {};
  }
  return password;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::close_wallet()
{
  bool r = m_wallet->deinit();
  if (!r)
  {
    fail_msg_writer() << ("failed to deinitialize wallet");
    return false;
  }

  try
  {
    m_wallet->store();
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << std::string(e.what());
    return false;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::start_mining(const std::vector<std::string>& args)
{
  if (!try_connect_to_daemon())
    return true;

  if (!m_wallet)
  {
    fail_msg_writer() << ("wallet is null");
    return true;
  }
  COMMAND_RPC_START_MINING::request req = AUTO_VAL_INIT(req);
  req.miner_address = m_wallet->get_account().get_public_address_str(m_wallet->nettype());

  bool ok = true;
  size_t arg_size = args.size();
  if(arg_size >= 1)
  {
    uint16_t num = 1;
    ok = epee::string_tools::get_xtype_from_string(num, args[0]);
    ok = ok && 1 <= num;
    req.threads_count = num;
  }
  else
  {
    req.threads_count = 1;
  }

  if (!ok)
  {
    PRINT_USAGE(USAGE_START_MINING);
    return true;
  }

  COMMAND_RPC_START_MINING::response res;
  bool r = m_wallet->get_rpc_client().invoke_http_json("/start_mining", req, res);
  std::string err = interpret_rpc_response(r, res.status);
  if (err.empty())
    success_msg_writer() << ("Mining started in daemon");
  else
    fail_msg_writer() << ("mining has NOT been started: ") << err;
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::stop_mining(const std::vector<std::string>& args)
{
  if (!try_connect_to_daemon())
    return true;

  if (!m_wallet)
  {
    fail_msg_writer() << ("wallet is null");
    return true;
  }

  COMMAND_RPC_STOP_MINING::request req;
  COMMAND_RPC_STOP_MINING::response res;
  bool r = m_wallet->get_rpc_client().invoke_http_json("/stop_mining", req, res);
  std::string err = interpret_rpc_response(r, res.status);
  if (err.empty())
    success_msg_writer() << ("Mining stopped in daemon");
  else
    fail_msg_writer() << ("mining has NOT been stopped: ") << err;
  return true;
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_new_block(uint64_t height, const cryptonote::block& block)
{
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount, const cryptonote::subaddress_index& subaddr_index, bool is_change, uint64_t unlock_height)
{
  message_writer(epee::console_colors::green, false) << "\r" <<
    ("Height ") << height << ", " <<
    ("txid ") << txid << ", " <<
    print_money(amount) << ", " <<
    ("idx ") << subaddr_index;

  if (unlock_height && !cryptonote::is_coinbase(tx))
    message_writer() << ("NOTE: This transaction is locked, see details with: show_transfer ") + epee::string_tools::pod_to_hex(txid);
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_unconfirmed_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount, const cryptonote::subaddress_index& subaddr_index)
{
  // Not implemented in CLI wallet
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_money_spent(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& in_tx, uint64_t amount, const cryptonote::transaction& spend_tx, const cryptonote::subaddress_index& subaddr_index)
{
  message_writer(epee::console_colors::magenta, false) << "\r" <<
    ("Height ") << height << ", " <<
    ("txid ") << txid << ", " <<
    ("spent ") << print_money(amount) << ", " <<
    ("idx ") << subaddr_index;
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_skip_transaction(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx)
{
}
//----------------------------------------------------------------------------------------------------
std::optional<epee::wipeable_string> simple_wallet::on_get_password(const char *reason)
{
  std::string msg = ("Enter password");
  if (reason && *reason)
    msg += std::string(" (") + reason + ")";
  auto pwd_container = tools::password_container::prompt(false, msg.c_str());
  if (!pwd_container)
  {
    LOG_ERROR("Failed to read password");
    return std::nullopt;
  }

  return pwd_container->password();
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_refresh_finished(uint64_t start_height, uint64_t fetched_blocks, bool is_init, bool received_money)
{
  const uint64_t rfbh = m_wallet->get_refresh_from_block_height();
  std::string err;
  const uint64_t dh = m_wallet->get_daemon_blockchain_height(err);
  if (err.empty() && rfbh > dh)
  {
    message_writer(epee::console_colors::yellow, false) << ("The wallet's refresh-from-block-height setting is higher than the daemon's height: this may mean your wallet will skip over transactions");
  }
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::refresh_main(uint64_t start_height, enum ResetType reset, bool is_init)
{
  if (!try_connect_to_daemon(is_init))
    return true;

  if (reset != ResetNone)
  {
    m_wallet->rescan_blockchain(reset == ResetHard, false);
  }

  message_writer() << ("Starting refresh...");

  uint64_t fetched_blocks = 0;
  bool received_money = false;
  bool ok = false;
  std::ostringstream ss;
  try
  {
    m_wallet->refresh(start_height, fetched_blocks, received_money);

    ok = true;
    success_msg_writer(true) << ("Refresh done, blocks received: ") << fetched_blocks;
    if (is_init)
      print_accounts();
    show_balance_unlocked();
    on_refresh_finished(start_height, fetched_blocks, is_init, received_money);
  }
  catch (const tools::error::daemon_busy&)
  {
    ss << ("daemon is busy. Please try again later.");
  }
  catch (const tools::error::no_connection_to_daemon&)
  {
    ss << ("no connection to daemon. Please make sure daemon is running.");
  }
  catch (const tools::error::wallet_rpc_error& e)
  {
    LOG_ERROR("RPC error: " + e.to_string());
    ss << ("RPC error: ") + std::string(e.what());
  }
  catch (const tools::error::refresh_error& e)
  {
    LOG_ERROR("refresh error: " + e.to_string());
    ss << ("refresh error: ") + std::string(e.what());
  }
  catch (const tools::error::wallet_internal_error& e)
  {
    LOG_ERROR("internal error: " + e.to_string());
    ss << ("internal error: ") + std::string(e.what());
  }
  catch (const std::exception& e)
  {
    LOG_ERROR("unexpected error: " + std::string(e.what()));
    ss << ("unexpected error: ") + std::string(e.what());
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    ss << ("unknown error");
  }

  if (!ok)
  {
    fail_msg_writer() << ("refresh failed: ") << ss.str() << ". " << ("Blocks received: ") << fetched_blocks;
  }

  // prevent it from triggering the idle screen due to waiting for a foreground refresh

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::refresh(const std::vector<std::string>& args)
{
  uint64_t start_height = 0;
  if(!args.empty()){
    try
    {
        start_height = boost::lexical_cast<uint64_t>( args[0] );
    }
    catch(const boost::bad_lexical_cast &)
    {
        start_height = 0;
    }
  }
  return refresh_main(start_height, ResetNone);
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_balance_unlocked(bool detailed)
{
  std::string extra;
  if (m_wallet->has_unknown_output_key_images())
    extra += (" (Some owned outputs have missing key images - import_output_key_images needed)");
  success_msg_writer() << ("Currently selected account: [") << m_current_subaddress_account << ("] ") << m_wallet->get_subaddress_label({m_current_subaddress_account, 0});
  uint64_t unlocked_balance = m_wallet->unlocked_balance(m_current_subaddress_account, false);

  success_msg_writer() << ("Balance: ") << print_money(m_wallet->balance(m_current_subaddress_account, false)) << ", "
    << ("unlocked balance: ") << print_money(unlocked_balance) << extra;

  std::map<uint32_t, uint64_t> balance_per_subaddress = m_wallet->balance_per_subaddress(m_current_subaddress_account, false);
  std::map<uint32_t, std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> unlocked_balance_per_subaddress = m_wallet->unlocked_balance_per_subaddress(m_current_subaddress_account, false);
  if (!detailed || balance_per_subaddress.empty())
    return true;
  success_msg_writer() << ("Balance per address:");
  success_msg_writer() << boost::format("%15s %21s %21s %7s %21s") % ("Address") % ("Balance") % ("Unlocked balance") % ("Outputs") % ("Label");
  const std::vector<wallet::logic::type::transfer::transfer_details> transfers = m_wallet->get_transfers();
  for (const auto& i : balance_per_subaddress)
  {
    cryptonote::subaddress_index subaddr_index = {m_current_subaddress_account, i.first};
    std::string address_str = m_wallet->get_subaddress_as_str(subaddr_index).substr(0, 6);
    uint64_t num_unspent_outputs = std::count_if(transfers.begin(), transfers.end(), [&subaddr_index](const wallet::logic::type::transfer::transfer_details& td) { return !td.m_spent && td.m_subaddr_index == subaddr_index; });
    success_msg_writer() << boost::format(tr("%8u %6s %21s %21s %7u %21s")) % i.first % address_str % print_money(i.second) % print_money(unlocked_balance_per_subaddress[i.first].first) % num_unspent_outputs % m_wallet->get_subaddress_label(subaddr_index);
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_balance(const std::vector<std::string>& args/* = std::vector<std::string>()*/)
{
  if (args.size() > 1 || (args.size() == 1 && args[0] != "detail"))
  {
    PRINT_USAGE(USAGE_SHOW_BALANCE);
    return true;
  }
  show_balance_unlocked(args.size() == 1);
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_incoming(const std::vector<std::string>& args)
{
  if (args.size() > 3)
  {
    PRINT_USAGE(USAGE_INCOMING);
    return true;
  }
  auto local_args = args;

  bool filter = false;
  bool available = false;
  bool verbose = false;
  if (local_args.size() > 0)
  {
    if (local_args[0] == "available")
    {
      filter = true;
      available = true;
      local_args.erase(local_args.begin());
    }
    else if (local_args[0] == "unavailable")
    {
      filter = true;
      available = false;
      local_args.erase(local_args.begin());
    }
  }
  while (local_args.size() > 0)
  {
    if (local_args[0] == "verbose")
      verbose = true;
    else
    {
      fail_msg_writer() << ("Invalid keyword: ") << local_args.front();
      break;
    }
    local_args.erase(local_args.begin());
  }

  std::set<uint32_t> subaddr_indices;
  if (local_args.size() > 0 && local_args[0].substr(0, 6) == "index=")
  {
    if (!parse_subaddress_indices(local_args[0], subaddr_indices))
      return true;
    local_args.erase(local_args.begin());
  }

  if (local_args.size() > 0)
  {
    PRINT_USAGE(USAGE_INCOMING);
    return true;
  }

  const wallet::logic::type::wallet::transfer_container transfers = m_wallet->get_transfers();

  size_t transfers_found = 0;
  for (const auto& td : transfers)
  {
    if (!filter || available != td.m_spent)
    {
      if (m_current_subaddress_account != td.m_subaddr_index.major || (!subaddr_indices.empty() && subaddr_indices.count(td.m_subaddr_index.minor) == 0))
        continue;
      if (!transfers_found)
      {
        std::string verbose_string;
        if (verbose)
          verbose_string = (boost::format("%68s%68s") % ("pubkey") % ("key image")).str();
        message_writer() << boost::format("%21s%8s%12s%8s%16s%68s%16s%s") % ("amount") % ("spent") % ("unlocked") % ("ringct") % ("global index") % ("tx id") % ("addr index") % verbose_string;
      }
      std::string extra_string;
      if (verbose)
        extra_string += (boost::format("%68s%68s") % td.get_public_key() % (td.m_output_key_image_known ? epee::string_tools::pod_to_hex(td.m_output_key_image) : td.m_output_key_image_partial ? (epee::string_tools::pod_to_hex(td.m_output_key_image) + "/p") : std::string(64, '?'))).str();
      message_writer(td.m_spent ? epee::console_colors::magenta : epee::console_colors::green, false) <<
        boost::format("%21s%8s%12s%8s%16u%68s%16u%s") %
        print_money(td.amount()) %
        (td.m_spent ? ("T") : ("F")) %
        (wallet::logic::functional::wallet::is_transfer_unlocked(td, m_wallet->get_blockchain_current_height())
         ? ("unlocked")
         : ("locked")) %
        (td.is_rct() ? ("RingCT") : ("-")) %
        td.m_global_output_index %
        td.m_txid %
        td.m_subaddr_index.minor %
        extra_string;
      ++transfers_found;
    }
  }

  if (!transfers_found)
  {
    if (!filter)
    {
      success_msg_writer() << ("No incoming transfers");
    }
    else if (available)
    {
      success_msg_writer() << ("No incoming available transfers");
    }
    else
    {
      success_msg_writer() << ("No incoming unavailable transfers");
    }
  }
  else
  {
    success_msg_writer() << boost::format("Found %u/%u transfers") % transfers_found % transfers.size();
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
uint64_t simple_wallet::get_daemon_blockchain_height(std::string& err)
{
  if (!m_wallet)
  {
    throw std::runtime_error("simple_wallet null wallet");
  }
  return m_wallet->get_daemon_blockchain_height(err);
}
//----------------------------------------------------------------------------------------------------
std::pair<std::string, std::string> simple_wallet::show_outputs_line(const std::vector<uint64_t> &heights, uint64_t blockchain_height, uint64_t highlight_idx) const
{
  std::stringstream ostr;

  for (uint64_t h: heights)
    blockchain_height = std::max(blockchain_height, h);

  for (size_t j = 0; j < heights.size(); ++j)
    ostr << (j == highlight_idx ? " *" : " ") << heights[j];

  // visualize the distribution, using the code by moneroexamples onion-monero-viewer
  const uint64_t resolution = 79;
  std::string ring_str(resolution, '_');
  for (size_t j = 0; j < heights.size(); ++j)
  {
    uint64_t pos = (heights[j] * resolution) / blockchain_height;
    ring_str[pos] = 'o';
  }
  if (highlight_idx < heights.size() && heights[highlight_idx] < blockchain_height)
  {
    uint64_t pos = (heights[highlight_idx] * resolution) / blockchain_height;
    ring_str[pos] = '*';
  }

  return std::make_pair(ostr.str(), ring_str);
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::process_ring_members(const std::vector<wallet::logic::type::tx::pending_tx>& ptx_vector, std::ostream& ostr)
{
  uint32_t version;
  if (!try_connect_to_daemon(false, &version))
  {
    fail_msg_writer() << ("failed to connect to daemon");
    return false;
  }
  // available for RPC version 1.4 or higher
  if (version < MAKE_CORE_RPC_VERSION(1, 4))
    return true;
  std::string err;
  uint64_t blockchain_height = get_daemon_blockchain_height(err);
  if (!err.empty())
  {
    fail_msg_writer() << ("failed to get blockchain height: ") << err;
    return false;
  }
  // for each transaction
  for (size_t n = 0; n < ptx_vector.size(); ++n)
  {
    const cryptonote::transaction& tx = ptx_vector[n].tx;
    const wallet::logic::type::tx::tx_construction_data& construction_data = ptx_vector[n].construction_data;
    // for each input
    std::vector<uint64_t>     spent_key_height(tx.vin.size());
    std::vector<crypto::hash> spent_key_txid  (tx.vin.size());
    for (size_t i = 0; i < tx.vin.size(); ++i)
    {
      if (tx.vin[i].type() != typeid(cryptonote::txin_from_key))
        continue;
      const cryptonote::txin_from_key& in_key = boost::get<cryptonote::txin_from_key>(tx.vin[i]);
      const wallet::logic::type::transfer::transfer_details &td = m_wallet->get_transfer_details(construction_data.selected_transfers[i]);
      const cryptonote::tx_source_entry *sptr = NULL;
      for (const auto &src: construction_data.sources)
        if (src.outputs[src.real_output].second.output_public_key == td.get_public_key())
          sptr = &src;
      if (!sptr)
      {
        fail_msg_writer() << ("failed to find construction data for tx input");
        return false;
      }
      const cryptonote::tx_source_entry& source = *sptr;

      // convert relative offsets of ring member keys into absolute offsets (indices) associated with the amount
      std::vector<uint64_t> absolute_offsets = cryptonote::relative_output_offsets_to_absolute(in_key.output_relative_offsets);
      // get block heights from which those ring member keys originated
      COMMAND_RPC_GET_OUTPUTS::request req = AUTO_VAL_INIT(req);
      req.outputs.resize(absolute_offsets.size());
      for (size_t j = 0; j < absolute_offsets.size(); ++j)
      {
        req.outputs[j].amount = in_key.amount;
        req.outputs[j].index = absolute_offsets[j];
      }
      COMMAND_RPC_GET_OUTPUTS::response res = AUTO_VAL_INIT(res);
      req.get_txid = true;

      bool r = m_wallet->get_rpc_client().invoke_http_json("/get_tx_outputs", req, res);
      err = interpret_rpc_response(r, res.status);
      if (!err.empty())
      {
        fail_msg_writer() << ("failed to get output: ") << err;
        return false;
      }

      std::vector<COMMAND_RPC_GET_OUTPUTS_BIN::outkey> res_outputs;
      std::transform
        (
         res.outs.begin()
         , res.outs.end()
         , std::back_inserter(res_outputs)
         , tools::rpc::parse_tx_output_result
         );

      // make sure that returned block heights are less than blockchain height
      for (const auto& res_out : res_outputs)
      {
        if (res_out.height >= blockchain_height)
        {
          fail_msg_writer() << ("output key's originating block height shouldn't be higher than the blockchain height");
          return false;
        }
      }
      spent_key_height[i] = res_outputs[source.real_output].height;
      spent_key_txid  [i] = res_outputs[source.real_output].txid;
      std::vector<uint64_t> heights(absolute_offsets.size(), 0);
      for (size_t j = 0; j < absolute_offsets.size(); ++j)
      {
        heights[j] = res_outputs[j].height;
      }
      std::pair<std::string, std::string> ring_str = show_outputs_line(heights, blockchain_height, source.real_output);
    }
    // warn if rings contain keys originating from the same tx or temporally very close block heights
    bool are_keys_from_same_tx      = false;
    bool are_keys_from_close_height = false;
    for (size_t i = 0; i < tx.vin.size(); ++i) {
      for (size_t j = i + 1; j < tx.vin.size(); ++j)
      {
        if (spent_key_txid[i] == spent_key_txid[j])
          are_keys_from_same_tx = true;
        if (std::abs((int64_t)(spent_key_height[i] - spent_key_height[j])) < (int64_t)5)
          are_keys_from_close_height = true;
      }
    }
    if (are_keys_from_same_tx || are_keys_from_close_height)
    {
      ostr
        << ("\nWarning: Some input keys being spent are from ")
        << (are_keys_from_same_tx ? ("the same transaction") : ("blocks that are temporally very close"))
        << (", which can break the anonymity of ring signatures. Make sure this is intentional!");
    }
    ostr << std::endl;
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::on_command(bool (simple_wallet::*cmd)(const std::vector<std::string>&), const std::vector<std::string> &args)
{

  m_in_command = true;
  epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){
    m_in_command = false;
  });

  return (this->*cmd)(args);
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::transfer_main(int transfer_type, const std::vector<std::string> &args_)
{
  if (!try_connect_to_daemon())
    return true;

  std::vector<std::string> local_args = args_;

  if(local_args.size() == 0)
    {
      fail_msg_writer() << ("wrong number of arguments");
      return true;
    }

  std::set<uint32_t> subaddr_indices;
  if (local_args.size() > 0 && local_args[0].substr(0, 6) == "index=")
  {
    if (!parse_subaddress_indices(local_args[0], subaddr_indices))
      return true;
    local_args.erase(local_args.begin());
  }

  const std::optional<uint32_t> maybe_priority = wallet::functional::parse_priority(local_args[0]);
  if (local_args.size() > 0 && *maybe_priority)
    local_args.erase(local_args.begin());

  const uint32_t priority = m_wallet->adjust_priority(maybe_priority.value_or(0));

  size_t fake_outs_count = config::lol::mixin;

  uint64_t adjusted_fake_outs_count = m_wallet->adjust_mixin(fake_outs_count);
  if (adjusted_fake_outs_count > fake_outs_count)
  {
    fail_msg_writer() << (boost::format(tr("ring size %u is too small, minimum is %u")) % (fake_outs_count+1) % (adjusted_fake_outs_count+1)).str();
    return true;
  }
  if (adjusted_fake_outs_count < fake_outs_count)
  {
    fail_msg_writer() << (boost::format(tr("ring size %u is too large, maximum is %u")) % (fake_outs_count+1) % (adjusted_fake_outs_count+1)).str();
    return true;
  }

  const size_t min_args = (transfer_type == TransferLocked) ? 2 : 1;
  if(local_args.size() < min_args)
  {
     fail_msg_writer() << ("wrong number of arguments");
     return true;
  }

  std::vector<uint8_t> extra;

  uint64_t locked_blocks = 0;
  if (transfer_type == TransferLocked)
  {
    try
    {
      locked_blocks = boost::lexical_cast<uint64_t>(local_args.back());
    }
    catch (const std::exception &e)
    {
      fail_msg_writer() << ("bad locked_blocks parameter:") << " " << local_args.back();
      return true;
    }
    if (locked_blocks > 1000000)
    {
      fail_msg_writer() << ("Locked blocks too high, max 1000000 (˜4 yrs)");
      return true;
    }
    local_args.pop_back();
  }

  std::vector<cryptonote::address_parse_info> dsts_info;
  std::vector<cryptonote::tx_destination_entry> dsts;
  for (size_t i = 0; i < local_args.size(); )
  {
    dsts_info.emplace_back();
    cryptonote::address_parse_info & info = dsts_info.back();
    cryptonote::tx_destination_entry de;
    bool r = true;

    // check for a URI
    std::string address_uri, tx_description, recipient_name, error;
    std::vector<std::string> unknown_parameters;
    if (i + 1 < local_args.size())
    {
      r = cryptonote::get_account_address_from_str(info, m_wallet->nettype(), local_args[i]);
      const auto maybe_amount = cryptonote::parse_amount(local_args[i + 1]);
      if(!maybe_amount) {
        fail_msg_writer() << ("failed to parse amount: ") << local_args[i] << ' ' << local_args[i + 1];
      }
      de.amount = *maybe_amount;

      if(0 == de.amount)
      {
        fail_msg_writer() << ("amount is wrong: ") << local_args[i] << ' ' << local_args[i + 1] <<
          ", " << ("expected number from 0 to ") << print_money(std::numeric_limits<uint64_t>::max());
        return true;
      }
      de.original = local_args[i];
      i += 2;
    }
    else
    {
      if (boost::starts_with(local_args[i], "lolnero:"))
        fail_msg_writer() << ("Invalid last argument: ") << local_args.back() << ": " << error;
      else
        fail_msg_writer() << ("Invalid last argument: ") << local_args.back();
      return true;
    }

    if (!r)
    {
      fail_msg_writer() << ("failed to parse address");
      return true;
    }
    de.addr = info.address;
    de.is_subaddress = info.is_subaddress;

    dsts.push_back(de);
  }

  try
  {
    // figure out what tx will be necessary
    std::vector<wallet::logic::type::tx::pending_tx> ptx_vector;
    uint64_t bc_height, unlock_block = 0;
    std::string err;
    switch (transfer_type)
    {
      case TransferLocked:
        bc_height = get_daemon_blockchain_height(err);
        if (!err.empty())
        {
          fail_msg_writer() << ("failed to get blockchain height: ") << err;
          return true;
        }
        unlock_block = bc_height + locked_blocks;
        ptx_vector = m_wallet->create_transactions(dsts, fake_outs_count, unlock_block /* unlock_height */, priority, extra, m_current_subaddress_account, subaddr_indices);
      break;
      default:
        LOG_ERROR("Unknown transfer method, using default");
        /* FALLTHRU */
      case Transfer:
        ptx_vector = m_wallet->create_transactions(dsts, fake_outs_count, 0 /* unlock_height */, priority, extra, m_current_subaddress_account, subaddr_indices);
      break;
    }

    if (ptx_vector.empty())
    {
      fail_msg_writer() << ("No outputs found, or daemon is not ready");
      return true;
    }

    // if more than one tx necessary, prompt user to confirm
    if (m_wallet->always_confirm_transfers() || ptx_vector.size() > 1)
    {
        uint64_t total_sent = 0;
        uint64_t total_fee = 0;
        uint64_t dust_not_in_fee = 0;
        uint64_t dust_in_fee = 0;
        uint64_t change = 0;
        for (size_t n = 0; n < ptx_vector.size(); ++n)
        {
          total_fee += ptx_vector[n].fee;
          for (auto i: ptx_vector[n].selected_transfers)
            total_sent += m_wallet->get_transfer_details(i).amount();
          total_sent -= ptx_vector[n].change_dts.amount + ptx_vector[n].fee;
          change += ptx_vector[n].change_dts.amount;

          if (ptx_vector[n].dust_added_to_fee)
            dust_in_fee += ptx_vector[n].dust;
          else
            dust_not_in_fee += ptx_vector[n].dust;
        }

        std::stringstream prompt;
        for (size_t n = 0; n < ptx_vector.size(); ++n)
        {
          prompt << ("\nTransaction ") << (n + 1) << "/" << ptx_vector.size() << ":\n";
          subaddr_indices.clear();
          for (uint32_t i : ptx_vector[n].construction_data.subaddr_indices)
            subaddr_indices.insert(i);
          for (uint32_t i : subaddr_indices)
            prompt << boost::format(tr("Spending from address index %d\n")) % i;
          if (subaddr_indices.size() > 1)
            prompt << ("WARNING: Outputs of multiple addresses are being used together, which might potentially compromise your privacy.\n");
        }
        prompt << boost::format(tr("Sending %s.  ")) % print_money(total_sent);
        if (ptx_vector.size() > 1)
        {
          prompt << boost::format(tr("Your transaction needs to be split into %llu transactions.  "
            "This will result in a transaction fee being applied to each transaction, for a total fee of %s")) %
            ((unsigned long long)ptx_vector.size()) % print_money(total_fee);
        }
        else
        {
          prompt << boost::format(tr("The transaction fee is %s")) %
            print_money(total_fee);
        }
        if (dust_in_fee != 0) prompt << boost::format(tr(", of which %s is dust from change")) % print_money(dust_in_fee);
        if (dust_not_in_fee != 0)  prompt << (".") << std::endl << boost::format(tr("A total of %s from dust change will be sent to dust address"))
                                                   % print_money(dust_not_in_fee);
        if (transfer_type == TransferLocked)
        {
          float days = locked_blocks / 720.0f;
          prompt << boost::format(tr(".\nThis transaction (including %s change) will unlock on block %llu, in approximately %s days (assuming 2 minutes per block)")) % cryptonote::print_money(change) % ((unsigned long long)unlock_block) % days;
        }
        if (!process_ring_members(ptx_vector, prompt))
          return false;

        prompt << std::endl << ("Is this okay?");
        std::string accepted = input_line(prompt.str(), true);
        if (std::cin.eof())
          return true;
        if (!command_line::is_yes(accepted))
        {
          fail_msg_writer() << ("transaction cancelled.");

          return true;
        }
    }

    {
      commit_or_save(ptx_vector, m_do_not_relay);
    }
  }
  catch (const std::exception &e)
  {
    wallet::cli::controller::handle_transfer_exception(std::current_exception());
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    fail_msg_writer() << ("unknown error");
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::transfer(const std::vector<std::string> &args_)
{
  return transfer_main(Transfer, args_);
}
//----------------------------------------------------------------------------------------------------
// mutates local_args as it parses and consumes arguments
bool simple_wallet::get_transfers(std::vector<std::string>& local_args, std::vector<transfer_view>& transfers)
{
  bool in = true;
  bool out = true;
  bool pending = true;
  bool failed = true;
  bool pool = true;
  bool coinbase = true;
  uint64_t min_height = 0;
  uint64_t max_height = (uint64_t)-1;

  // optional in/out selector
  if (local_args.size() > 0) {
    if (local_args[0] == "in" || local_args[0] == "incoming") {
      out = pending = failed = false;
      local_args.erase(local_args.begin());
    }
    else if (local_args[0] == "out" || local_args[0] == "outgoing") {
      in = pool = coinbase = false;
      local_args.erase(local_args.begin());
    }
    else if (local_args[0] == "pending") {
      in = out = failed = coinbase = false;
      local_args.erase(local_args.begin());
    }
    else if (local_args[0] == "failed") {
      in = out = pending = pool = coinbase = false;
      local_args.erase(local_args.begin());
    }
    else if (local_args[0] == "pool") {
      in = out = pending = failed = coinbase = false;
      local_args.erase(local_args.begin());
    }
    else if (local_args[0] == "coinbase") {
      in = out = pending = failed = pool = false;
      coinbase = true;
      local_args.erase(local_args.begin());
    }
    else if (local_args[0] == "all" || local_args[0] == "both") {
      local_args.erase(local_args.begin());
    }
  }

  // subaddr_index
  std::set<uint32_t> subaddr_indices;
  if (local_args.size() > 0 && local_args[0].substr(0, 6) == "index=")
  {
    if (!parse_subaddress_indices(local_args[0], subaddr_indices))
      return false;
    local_args.erase(local_args.begin());
  }

  // min height
  if (local_args.size() > 0 && local_args[0].find('=') == std::string::npos) {
    try {
      min_height = boost::lexical_cast<uint64_t>(local_args[0]);
    }
    catch (const boost::bad_lexical_cast &) {
      fail_msg_writer() << ("bad min_height parameter:") << " " << local_args[0];
      return false;
    }
    local_args.erase(local_args.begin());
  }

  // max height
  if (local_args.size() > 0 && local_args[0].find('=') == std::string::npos) {
    try {
      max_height = boost::lexical_cast<uint64_t>(local_args[0]);
    }
    catch (const boost::bad_lexical_cast &) {
      fail_msg_writer() << ("bad max_height parameter:") << " " << local_args[0];
      return false;
    }
    local_args.erase(local_args.begin());
  }

  const uint64_t last_block_height = m_wallet->get_blockchain_current_height();

  if (in || coinbase) {
    std::list<std::pair<crypto::hash, wallet::logic::type::payment::payment_details>> payments;
    m_wallet->get_payments(payments, min_height, max_height, m_current_subaddress_account, subaddr_indices);
    for (std::list<std::pair<crypto::hash, wallet::logic::type::payment::payment_details>>::const_iterator i = payments.begin(); i != payments.end(); ++i) {
      const wallet::logic::type::payment::payment_details &pd = i->second;
      if (!pd.m_coinbase && !in)
        continue;
      std::string note;
      std::string destination = m_wallet->get_subaddress_as_str({m_current_subaddress_account, pd.m_subaddr_index.minor});
      const std::string type = pd.m_coinbase ? ("block") : ("in");
      const bool unlocked = wallet::logic::functional::wallet::is_transfer_unlocked
        (pd.m_unlock_height, pd.m_block_height, last_block_height);
      std::string locked_msg = "unlocked";
      if (!unlocked)
      {
        locked_msg = "locked";
        uint64_t bh = std::max(pd.m_unlock_height, pd.m_block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE);
        if (bh >= last_block_height)
          locked_msg = std::to_string(bh - last_block_height) + " blks";
      }
      transfers.push_back({
        type,
        pd.m_block_height,
        pd.m_timestamp,
        type,
        true,
        pd.m_amount,
        pd.m_tx_hash,
        0,
        {{destination, pd.m_amount}},
        {pd.m_subaddr_index.minor},
        note,
        locked_msg
      });
    }
  }

  if (out) {
    std::list<std::pair<crypto::hash, wallet::logic::type::transfer::confirmed_transfer_details>> payments;
    m_wallet->get_payments_out(payments, min_height, max_height, m_current_subaddress_account, subaddr_indices);
    for (std::list<std::pair<crypto::hash, wallet::logic::type::transfer::confirmed_transfer_details>>::const_iterator i = payments.begin(); i != payments.end(); ++i) {
      const wallet::logic::type::transfer::confirmed_transfer_details &pd = i->second;
      uint64_t change = pd.m_change == (uint64_t)-1 ? 0 : pd.m_change; // change may not be known
      uint64_t fee = pd.m_amount_in - pd.m_amount_out;
      std::vector<std::pair<std::string, uint64_t>> destinations;
      for (const auto &d: pd.m_dests) {
        destinations.push_back({d.address(m_wallet->nettype()), d.amount});
      }
      std::string note;
      transfers.push_back({
        "out",
        pd.m_block_height,
        pd.m_timestamp,
        "out",
        true,
        pd.m_amount_in - change - fee,
        i->first,
        fee,
        destinations,
        pd.m_subaddr_indices,
        note,
        "-"
      });
    }
  }

  if (pool) {
    try
    {
      std::vector<std::tuple<cryptonote::transaction, crypto::hash, bool>> process_txs;
      m_wallet->update_pool_state(process_txs);
      if (!process_txs.empty())
        m_wallet->process_pool_state(process_txs);

      std::list<std::pair<crypto::hash, wallet::logic::type::payment::pool_payment_details>> payments;
      m_wallet->get_unconfirmed_payments(payments, m_current_subaddress_account, subaddr_indices);
      for (std::list<std::pair<crypto::hash, wallet::logic::type::payment::pool_payment_details>>::const_iterator i = payments.begin(); i != payments.end(); ++i) {
        const wallet::logic::type::payment::payment_details &pd = i->second.m_pd;
        std::string note;
        std::string destination = m_wallet->get_subaddress_as_str({m_current_subaddress_account, pd.m_subaddr_index.minor});
        std::string double_spend_note;
        if (i->second.m_double_spend_seen)
          double_spend_note = ("[Double spend seen on the network: this transaction may or may not end up being mined] ");
        transfers.push_back({
          "pool",
          "pool",
          pd.m_timestamp,
          "in",
          false,
          pd.m_amount,
          pd.m_tx_hash,
          0,
          {{destination, pd.m_amount}},
          {pd.m_subaddr_index.minor},
          note + double_spend_note,
          "locked"
        });
      }
    }
    catch (const std::exception& e)
    {
      fail_msg_writer() << "Failed to get pool state:" + std::string(e.what());
    }
  }

  // print unconfirmed last
  if (pending || failed) {
    std::list<std::pair<crypto::hash, wallet::logic::type::transfer::unconfirmed_transfer_details>> upayments;
    m_wallet->get_unconfirmed_payments_out(upayments, m_current_subaddress_account, subaddr_indices);
    for (std::list<std::pair<crypto::hash, wallet::logic::type::transfer::unconfirmed_transfer_details>>::const_iterator i = upayments.begin(); i != upayments.end(); ++i) {
      const wallet::logic::type::transfer::unconfirmed_transfer_details &pd = i->second;
      uint64_t amount = pd.m_amount_in;
      uint64_t fee = amount - pd.m_amount_out;
      std::vector<std::pair<std::string, uint64_t>> destinations;
      for (const auto &d: pd.m_dests) {
        destinations.push_back({d.address(m_wallet->nettype()), d.amount});
      }
      std::string note;
      bool is_failed = pd.m_state == wallet::logic::type::transfer::unconfirmed_transfer_details::failed;
      if ((failed && is_failed) || (!is_failed && pending)) {
        transfers.push_back({
          (is_failed ? "failed" : "pending"),
          (is_failed ? "failed" : "pending"),
          pd.m_timestamp,
          "out",
          false,
          amount - pd.m_change - fee,
          i->first,
          fee,
          destinations,
          pd.m_subaddr_indices,
          note,
          "-"
        });
      }
    }
  }
  // sort by block, then by timestamp (unconfirmed last)
  std::sort(transfers.begin(), transfers.end(), [](const transfer_view& a, const transfer_view& b) -> bool {
    if (a.confirmed && !b.confirmed)
      return true;
    if (a.block == b.block)
      return a.timestamp < b.timestamp;
    return a.block < b.block;
  });

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show(const std::vector<std::string> &args_)
{
  std::vector<std::string> local_args = args_;

  if(local_args.size() > 4) {
    fail_msg_writer() << USAGE_SHOW;
    return true;
  }

  std::vector<transfer_view> all_transfers;

  if (!get_transfers(local_args, all_transfers))
    return true;

  for (const auto& transfer : all_transfers)
  {
    const auto color = transfer.type == "failed" ? epee::console_colors::red : transfer.confirmed ? ((transfer.direction == "in" || transfer.direction == "block") ? epee::console_colors::green : epee::console_colors::magenta) : epee::console_colors::color_default;

    std::string destinations = "-";
    if (!transfer.outputs.empty())
    {
      destinations = "";
      for (const auto& output : transfer.outputs)
      {
        if (!destinations.empty())
          destinations += ", ";
        destinations += (transfer.direction == "in" ? output.first.substr(0, 6) : output.first) + ":" + print_money(output.second);
      }
    }

    auto formatter = boost::format("%8.8llu %6.6s %8.8s %25.25s %20.20s %s %14.14s %s %s - %s");

    message_writer(color, false) << formatter
      % transfer.block
      % transfer.direction
      % transfer.unlocked
      % tools::get_human_readable_timestamp(transfer.timestamp)
      % print_money(transfer.amount)
      % epee::string_tools::pod_to_hex(transfer.hash)
      % print_money(transfer.fee)
      % destinations
      % boost::algorithm::join(transfer.index | boost::adaptors::transformed([](uint32_t i) { return std::to_string(i); }), ", ")
      % transfer.note;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::rescan_blockchain(const std::vector<std::string> &args_)
{
  ResetType reset_type = ResetSoft;
  if (!args_.empty())
  {
    if (args_[0] == "hard")
    {
      reset_type = ResetHard;
    }
    else {
      PRINT_USAGE(USAGE_RESCAN);
      return true;
    }
  }

  if (reset_type == ResetHard)
  {
    message_writer() << ("Warning: this will lose any information which can not be recovered from the blockchain.");
    message_writer() << ("This includes destination addresses, tx secret keys, tx notes, etc");
    std::string confirm = input_line(tr("Rescan anyway?"), true);
    if(!std::cin.eof())
    {
      if (!command_line::is_yes(confirm))
        return true;
    }
  }

  return refresh_main(0, reset_type, true);
}
//----------------------------------------------------------------------------------------------------
std::string simple_wallet::get_prompt() const
{
  std::string addr_start = m_wallet->get_subaddress_as_str({m_current_subaddress_account, 0}).substr(0, 6);
  std::string prompt = std::string("[") + ("wallet") + " " + addr_start;
  if (!m_wallet->check_connection(NULL))
    prompt += " (no daemon)";
  else if (!m_wallet->is_synced())
    prompt += " (out of sync)";
  prompt += "]: ";
  return prompt;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::run()
{
  // check and display warning, but go on anyway
  try_connect_to_daemon();

  refresh_main(0, ResetNone, true);

  return m_cmd_binder.run_handling([this](){return get_prompt();}, "");
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::stop()
{
  m_cmd_binder.stop_handling();
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::account(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  // Usage:
  //   account
  //   account new <label>
  //   account switch <index>
  //   account label <index> <label>

  if (args.empty())
  {
    // print all the existing accounts
    print_accounts();
    return true;
  }

  std::vector<std::string> local_args = args;
  std::string command = local_args[0];
  local_args.erase(local_args.begin());
  if (command == "new")
  {
    // create a new account and switch to it
    std::string label = boost::join(local_args, " ");
    if (label.empty())
      label = ("(Untitled account)");
    m_wallet->add_subaddress_account(label);
    m_current_subaddress_account = m_wallet->get_num_subaddress_accounts() - 1;
    // update_prompt();
    print_accounts();
  }
  else if (command == "switch" && local_args.size() == 1)
  {
    // switch to the specified account
    uint32_t index_major;
    if (!epee::string_tools::get_xtype_from_string(index_major, local_args[0]))
    {
      fail_msg_writer() << ("failed to parse index: ") << local_args[0];
      return true;
    }
    if (index_major >= m_wallet->get_num_subaddress_accounts())
    {
      fail_msg_writer() << ("specify an index between 0 and ") << (m_wallet->get_num_subaddress_accounts() - 1);
      return true;
    }
    m_current_subaddress_account = index_major;
    // update_prompt();
    show_balance();
  }
  else if (command == "label" && local_args.size() >= 1)
  {
    // set label of the specified account
    uint32_t index_major;
    if (!epee::string_tools::get_xtype_from_string(index_major, local_args[0]))
    {
      fail_msg_writer() << ("failed to parse index: ") << local_args[0];
      return true;
    }
    local_args.erase(local_args.begin());
    std::string label = boost::join(local_args, " ");
    try
    {
      m_wallet->set_subaddress_label({index_major, 0}, label);
      print_accounts();
    }
    catch (const std::exception& e)
    {
      fail_msg_writer() << std::string(e.what());
    }
  }
  else
  {
    PRINT_USAGE(USAGE_ACCOUNT);
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::print_accounts()
{
  success_msg_writer() << boost::format("  %15s %21s %21s %21s") % ("Account") % ("Balance") % ("Unlocked balance") % ("Label");
  uint64_t total_balance = 0, total_unlocked_balance = 0;
  for (uint32_t account_index = 0; account_index < m_wallet->get_num_subaddress_accounts(); ++account_index)
  {
    success_msg_writer() << boost::format(tr(" %c%8u %6s %21s %21s %21s"))
      % (m_current_subaddress_account == account_index ? '*' : ' ')
      % account_index
      % m_wallet->get_subaddress_as_str({account_index, 0}).substr(0, 6)
      % print_money(m_wallet->balance(account_index, false))
      % print_money(m_wallet->unlocked_balance(account_index, false))
      % m_wallet->get_subaddress_label({account_index, 0});
    total_balance += m_wallet->balance(account_index, false);
    total_unlocked_balance += m_wallet->unlocked_balance(account_index, false);
  }
  success_msg_writer() << ("----------------------------------------------------------------------------------");
  success_msg_writer() << boost::format(tr("%15s %21s %21s")) % "Total" % print_money(total_balance) % print_money(total_unlocked_balance);
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::print_address(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  // Usage:
  //  address
  //  address new <label>
  //  address all
  //  address <index min> [<index max>]
  //  address label <index> <label>
  //  address device [<index>]

  std::vector<std::string> local_args = args;
  const wallet::logic::type::wallet::transfer_container transfers = m_wallet->get_transfers();

  auto print_address_sub = [this, &transfers](uint32_t index)
  {
    bool used = std::find_if(
      transfers.begin(), transfers.end(),
      [this, &index](const wallet::logic::type::transfer::transfer_details& td) {
        return td.m_subaddr_index == cryptonote::subaddress_index{ m_current_subaddress_account, index };
      }) != transfers.end();
    success_msg_writer() << index << "  " << m_wallet->get_subaddress_as_str({m_current_subaddress_account, index}) << "  " << m_wallet->get_subaddress_label({m_current_subaddress_account, index}) << " " << (used ? ("(used)") : "");
  };

  uint32_t index = 0;
  if (local_args.empty())
  {
    print_address_sub(0);
  }
  else if (local_args.size() == 1 && local_args[0] == "all")
  {
    local_args.erase(local_args.begin());
    for (; index < m_wallet->get_num_subaddresses(m_current_subaddress_account); ++index)
      print_address_sub(index);
  }
  else if (local_args[0] == "new")
  {
    local_args.erase(local_args.begin());
    std::string label;
    if (local_args.size() > 0)
      label = boost::join(local_args, " ");
    m_wallet->add_subaddress(m_current_subaddress_account, label);
    print_address_sub(m_wallet->get_num_subaddresses(m_current_subaddress_account) - 1);
  }
  else if (local_args[0] == "one-off")
  {
    local_args.erase(local_args.begin());
    std::string label;
    if (local_args.size() != 2)
    {
      fail_msg_writer() << ("Expected exactly two arguments for index");
      return true;
    }
    uint32_t major, minor;
    if (!epee::string_tools::get_xtype_from_string(major, local_args[0]) || !epee::string_tools::get_xtype_from_string(minor, local_args[1]))
    {
      fail_msg_writer() << ("failed to parse index: ") << local_args[0] << " " << local_args[1];
      return true;
    }
    m_wallet->create_one_off_subaddress({major, minor});
    success_msg_writer() << boost::format(tr("Address at %u %u: %s")) % major % minor % m_wallet->get_subaddress_as_str({major, minor});
  }
  else if (local_args.size() >= 2 && local_args[0] == "label")
  {
    if (!epee::string_tools::get_xtype_from_string(index, local_args[1]))
    {
      fail_msg_writer() << ("failed to parse index: ") << local_args[1];
      return true;
    }
    if (index >= m_wallet->get_num_subaddresses(m_current_subaddress_account))
    {
      fail_msg_writer() << ("specify an index between 0 and ") << (m_wallet->get_num_subaddresses(m_current_subaddress_account) - 1);
      return true;
    }
    local_args.erase(local_args.begin());
    local_args.erase(local_args.begin());
    std::string label = boost::join(local_args, " ");
    m_wallet->set_subaddress_label({m_current_subaddress_account, index}, label);
    print_address_sub(index);
  }
  else if (local_args.size() <= 2 && epee::string_tools::get_xtype_from_string(index, local_args[0]))
  {
    local_args.erase(local_args.begin());
    uint32_t index_min = index;
    uint32_t index_max = index_min;
    if (local_args.size() > 0)
    {
      if (!epee::string_tools::get_xtype_from_string(index_max, local_args[0]))
      {
        fail_msg_writer() << ("failed to parse index: ") << local_args[0];
        return true;
      }
      local_args.erase(local_args.begin());
    }
    if (index_max < index_min)
      std::swap(index_min, index_max);
    if (index_min >= m_wallet->get_num_subaddresses(m_current_subaddress_account))
    {
      fail_msg_writer() << ("<index min> is already out of bound");
      return true;
    }
    if (index_max >= m_wallet->get_num_subaddresses(m_current_subaddress_account))
    {
      message_writer() << ("<index max> exceeds the bound");
      index_max = m_wallet->get_num_subaddresses(m_current_subaddress_account) - 1;
    }
    for (index = index_min; index <= index_max; ++index)
      print_address_sub(index);
  }
  else if (local_args[0] == "device")
  {
    index = 0;
    local_args.erase(local_args.begin());
    if (local_args.size() > 0)
    {
      if (!epee::string_tools::get_xtype_from_string(index, local_args[0]))
      {
        fail_msg_writer() << ("failed to parse index: ") << local_args[0];
        return true;
      }
      if (index >= m_wallet->get_num_subaddresses(m_current_subaddress_account))
      {
        fail_msg_writer() << ("<index> is out of bounds");
        return true;
      }
    }

    print_address_sub(index);
  }
  else
  {
    PRINT_USAGE(USAGE_ADDRESS);
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::status(const std::vector<std::string> &args)
{
  uint64_t local_height = m_wallet->get_blockchain_current_height();
  uint32_t version = 0;
  if (!m_wallet->check_connection(&version))
  {
    success_msg_writer() << "Refreshed " << local_height << "/?, no daemon connected";
    return true;
  }

  std::string err;
  uint64_t bc_height = get_daemon_blockchain_height(err);
  if (err.empty())
  {
    bool synced = local_height == bc_height;
    success_msg_writer() << "Refreshed " << local_height << "/" << bc_height
                         << ", " << (synced ? "synced" : "syncing")
                         << ", daemon RPC v" << get_version_string(version);
  }
  else
  {
    fail_msg_writer() << "Refreshed " << local_height << "/?, daemon connection error";
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_tx(const std::vector<std::string> &args)
{
  if (args.size() != 1)
  {
    PRINT_USAGE(USAGE_SHOW_TX);
    return true;
  }

  cryptonote::string_blob txid_data;
  if(!epee::string_tools::parse_hexstr_to_binbuff(args.front(), txid_data) || txid_data.size() != sizeof(crypto::hash))
  {
    fail_msg_writer() << ("failed to parse txid");
    return true;
  }
  crypto::hash txid;
  std::copy(txid_data.begin(), txid_data.end(), txid.data.begin());

  const uint64_t last_block_height = m_wallet->get_blockchain_current_height();

  std::list<std::pair<crypto::hash, wallet::logic::type::payment::payment_details>> payments;
  m_wallet->get_payments(payments, 0, (uint64_t)-1, m_current_subaddress_account);
  for (std::list<std::pair<crypto::hash, wallet::logic::type::payment::payment_details>>::const_iterator i = payments.begin(); i != payments.end(); ++i) {
    const wallet::logic::type::payment::payment_details &pd = i->second;
    if (pd.m_tx_hash == txid) {
      success_msg_writer() << "Incoming transaction found";
      success_msg_writer() << "txid: " << txid;
      success_msg_writer() << "Height: " << pd.m_block_height;
      success_msg_writer() << "Timestamp: " << tools::get_human_readable_timestamp(pd.m_timestamp);
      success_msg_writer() << "Amount: " << print_money(pd.m_amount);
      uint64_t bh = std::max(pd.m_unlock_height, pd.m_block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE);
      uint64_t suggested_threshold = pd.m_amount + consensus::get_block_reward() - 1;
      if (bh >= last_block_height)
        success_msg_writer() << "Locked: " << (bh - last_block_height) << " blocks to unlock";
      else if (suggested_threshold > 0)
        success_msg_writer() << std::to_string(last_block_height - bh) << " confirmations (" << suggested_threshold << " suggested threshold)";
      else
        success_msg_writer() << std::to_string(last_block_height - bh) << " confirmations";
      success_msg_writer() << "Address index: " << pd.m_subaddr_index.minor;
      return true;
    }
  }

  std::list<std::pair<crypto::hash, wallet::logic::type::transfer::confirmed_transfer_details>> payments_out;
  m_wallet->get_payments_out(payments_out, 0, (uint64_t)-1, m_current_subaddress_account);
  for (std::list<std::pair<crypto::hash, wallet::logic::type::transfer::confirmed_transfer_details>>::const_iterator i = payments_out.begin(); i != payments_out.end(); ++i) {
    if (i->first == txid)
    {
      const wallet::logic::type::transfer::confirmed_transfer_details &pd = i->second;
      uint64_t change = pd.m_change == (uint64_t)-1 ? 0 : pd.m_change; // change may not be known
      uint64_t fee = pd.m_amount_in - pd.m_amount_out;
      std::string dests;
      for (const auto &d: pd.m_dests) {
        if (!dests.empty())
          dests += ", ";
        dests +=  d.address(m_wallet->nettype()) + ": " + print_money(d.amount);
      }
      success_msg_writer() << "Outgoing transaction found";
      success_msg_writer() << "txid: " << txid;
      success_msg_writer() << "Height: " << pd.m_block_height;
      success_msg_writer() << "Timestamp: " << tools::get_human_readable_timestamp(pd.m_timestamp);
      success_msg_writer() << "Amount: " << print_money(pd.m_amount_in - change - fee);
      success_msg_writer() << "Change: " << print_money(change);
      success_msg_writer() << "Fee: " << print_money(fee);
      success_msg_writer() << "Destinations: " << dests;
      return true;
    }
  }

  try
  {
    std::vector<std::tuple<cryptonote::transaction, crypto::hash, bool>> process_txs;
    m_wallet->update_pool_state(process_txs);
    if (!process_txs.empty())
      m_wallet->process_pool_state(process_txs);

    std::list<std::pair<crypto::hash, wallet::logic::type::payment::pool_payment_details>> pool_payments;
    m_wallet->get_unconfirmed_payments(pool_payments, m_current_subaddress_account);
    for (std::list<std::pair<crypto::hash, wallet::logic::type::payment::pool_payment_details>>::const_iterator i = pool_payments.begin(); i != pool_payments.end(); ++i) {
      const wallet::logic::type::payment::payment_details &pd = i->second.m_pd;
      if (pd.m_tx_hash == txid)
      {
        success_msg_writer() << "Unconfirmed incoming transaction found in the txpool";
        success_msg_writer() << "txid: " << txid;
        success_msg_writer() << "Timestamp: " << tools::get_human_readable_timestamp(pd.m_timestamp);
        success_msg_writer() << "Amount: " << print_money(pd.m_amount);
        success_msg_writer() << "Address index: " << pd.m_subaddr_index.minor;
        if (i->second.m_double_spend_seen)
          success_msg_writer() << ("Double spend seen on the network: this transaction may or may not end up being mined");
        return true;
      }
    }
  }
  catch (...)
  {
    fail_msg_writer() << "Failed to get pool state";
  }

  std::list<std::pair<crypto::hash, wallet::logic::type::transfer::unconfirmed_transfer_details>> upayments;
  m_wallet->get_unconfirmed_payments_out(upayments, m_current_subaddress_account);
  for (std::list<std::pair<crypto::hash, wallet::logic::type::transfer::unconfirmed_transfer_details>>::const_iterator i = upayments.begin(); i != upayments.end(); ++i) {
    if (i->first == txid)
    {
      const wallet::logic::type::transfer::unconfirmed_transfer_details &pd = i->second;
      uint64_t amount = pd.m_amount_in;
      uint64_t fee = amount - pd.m_amount_out;
      bool is_failed = pd.m_state == wallet::logic::type::transfer::unconfirmed_transfer_details::failed;

      success_msg_writer() << (is_failed ? "Failed" : "Pending") << " outgoing transaction found";
      success_msg_writer() << "txid: " << txid;
      success_msg_writer() << "Timestamp: " << tools::get_human_readable_timestamp(pd.m_timestamp);
      success_msg_writer() << "Amount: " << print_money(amount - pd.m_change - fee);
      success_msg_writer() << "Change: " << print_money(pd.m_change);
      success_msg_writer() << "Fee: " << print_money(fee);
      return true;
    }
  }

  fail_msg_writer() << ("Transaction ID not found");
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::process_command(const std::vector<std::string> &args)
{
  return m_cmd_binder.process_command_vec(args);
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::interrupt()
{
  m_wallet->stop();
  stop();
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::commit_or_save(std::vector<wallet::logic::type::tx::pending_tx>& ptx_vector, bool do_not_relay)
{
  size_t i = 0;
  while (!ptx_vector.empty())
  {
    auto & ptx = ptx_vector.back();
    const crypto::hash txid = get_transaction_hash(ptx.tx);
    if (do_not_relay)
    {
      cryptonote::string_blob blob = tx_to_blob(ptx.tx);
      const std::string blob_hex = epee::string_tools::buff_to_hex_nodelimer(blob);
      const std::string filename = "raw_lolnero_tx" + (ptx_vector.size() == 1 ? "" : ("_" + std::to_string(i++)));
      if (wallet::logic::controller::wallet::save_to_file(filename, blob_hex))
        success_msg_writer(true) << ("Transaction successfully saved to ") << filename << (", txid ") << txid;
      else
        fail_msg_writer() << ("Failed to save transaction to ") << filename << (", txid ") << txid;
    }
    else
    {
      m_wallet->commit_tx(ptx);
      success_msg_writer(true) << ("Transaction successfully submitted, transaction ") << txid << std::endl
      << ("You can check its status by using the `show` command.");
    }
    // if no exception, remove element from vector
    ptx_vector.pop_back();
  }
}

} // cryptonote

//----------------------------------------------------------------------------------------------------
int main(int argc, char* argv[])
{
  using namespace cryptonote;

  TRY_ENTRY();

  po::options_description desc_params(wallet_args::tr("Wallet options"));
  tools::wallet2::init_options(desc_params);
  command_line::add_arg(desc_params, wallet_args::arg_wallet_file());
  command_line::add_arg(desc_params, arg_generate_new_wallet);
  command_line::add_arg(desc_params, arg_generate_from_spend_key);

  command_line::add_arg(desc_params, arg_restore_deterministic_wallet );
  command_line::add_arg(desc_params, arg_electrum_seed );
  command_line::add_arg(desc_params, arg_do_not_relay);
  command_line::add_arg(desc_params, arg_subaddress_lookahead);

  po::positional_options_description positional_options;
  std::optional<po::variables_map> vm;

  bool should_terminate = false;
  std::tie(vm, should_terminate) = wallet_args::main
    (
     argc, argv,
     "lolnero [--open=<filename>|--new=<filename>]",
     "",
     desc_params,
     positional_options,
     [](const std::string &s, bool emphasis){
       tools::scoped_message_writer(emphasis ? epee::console_colors::white : epee::console_colors::color_default, true) << s;
     }
     );

  if (!vm)
  {
    return 1;
  }

  if (should_terminate)
  {
    return 0;
  }

  cryptonote::simple_wallet w;
  const bool r = w.init(*vm);
  LOG_ERROR_AND_RETURN_UNLESS(r, 1, ("Failed to initialize wallet"));

  {
    tools::signal_handler_install([&w](int type) {
      if (tools::password_container::is_prompting.load())
      {
        // must be prompting for password so return and let the signal stop prompt
        return;
      }
      if (type == SIGINT)
      {
        // if we're pressing ^C when refreshing, just stop refreshing
        w.interrupt();
      }
      else
      {
        w.stop();
      }
    });
    w.run();

    w.deinit();
  }
  return 0;
  CATCH_ENTRY_L0("main", 1);
}

