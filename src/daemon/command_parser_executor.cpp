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

#include "command_parser_executor.h"


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "daemon"

namespace daemonize {

t_command_parser_executor::t_command_parser_executor(
    uint32_t ip
  , uint16_t port
  , const epee::net_utils::ssl_options_t& ssl_options
  , bool is_rpc
  , cryptonote::core_rpc_server* rpc_server
  )
  : m_executor(ip, port, ssl_options, is_rpc, rpc_server)
{}

bool t_command_parser_executor::print_peer_list(const std::vector<std::string>& args)
{
  if (args.size() > 3)
  {
    std::cout << "Invalid syntax: Too many parameters. For more details, use the help command." << std::endl;
    return true;
  }

  bool white = false;
  bool gray = false;
  size_t limit = 0;
  for (size_t i = 0; i < args.size(); ++i)
  {
    if (args[i] == "white")
    {
      white = true;
    }
    else if (args[i] == "gray")
    {
      gray = true;
    }
    else if (!epee::string_tools::get_xtype_from_string(limit, args[i]))
    {
      std::cout << "Invalid syntax: Unexpected parameter: " << args[i] << ". For more details, use the help command." << std::endl;
      return true;
    }
  }

  const bool print_both = !white && !gray;
  return m_executor.print_peer_list(white | print_both, gray | print_both, limit);
}

bool t_command_parser_executor::print_peer_list_stats(const std::vector<std::string>& args)
{
  if (!args.empty()) {
    std::cout << "Invalid syntax: No parameters expected. For more details, use the help command." << std::endl;
    return true;
  }

  return m_executor.print_peer_list_stats();
}

bool t_command_parser_executor::save_blockchain(const std::vector<std::string>& args)
{
  if (!args.empty()) {
    std::cout << "Invalid syntax: No parameters expected. For more details, use the help command." << std::endl;
    return true;
  }
  return m_executor.save_blockchain();
}

bool t_command_parser_executor::show_difficulty(const std::vector<std::string>& args)
{
  if (!args.empty()) {
    std::cout << "Invalid syntax: No parameters expected. For more details, use the help command." << std::endl;
    return true;
  }

  return m_executor.show_difficulty();
}

bool t_command_parser_executor::show_status(const std::vector<std::string>& args)
{
  if (!args.empty()) {
    std::cout << "Invalid syntax: No parameters expected. For more details, use the help command." << std::endl;
    return true;
  }

  return m_executor.show_status();
}

bool t_command_parser_executor::print_connections(const std::vector<std::string>& args)
{
  if (!args.empty()) {
    std::cout << "Invalid syntax: No parameters expected. For more details, use the help command." << std::endl;
    return true;
  }

  return m_executor.print_connections();
}

bool t_command_parser_executor::print_blockchain_info(const std::vector<std::string>& args)
{
  if(!args.size())
  {
    std::cout << "Invalid syntax: At least one parameter expected. For more details, use the help command." << std::endl;
    return true;
  }
  uint64_t start_index = 0;
  uint64_t end_index = 0;
  if (args[0][0] == '-')
  {
    int64_t nblocks;
    if(!epee::string_tools::get_xtype_from_string(nblocks, args[0]))
    {
      std::cout << "Invalid syntax: Wrong number of blocks. For more details, use the help command." << std::endl;
      return true;
    }
    return m_executor.print_blockchain_info(nblocks, (uint64_t)-nblocks);
  }
  if(!epee::string_tools::get_xtype_from_string(start_index, args[0]))
  {
    std::cout << "Invalid syntax: Wrong starter block index parameter. For more details, use the help command." << std::endl;
    return true;
  }
  if(args.size() >1 && !epee::string_tools::get_xtype_from_string(end_index, args[1]))
  {
    std::cout << "Invalid syntax: Wrong end block index parameter. For more details, use the help command." << std::endl;
    return true;
  }

  return m_executor.print_blockchain_info(start_index, end_index);
}

bool t_command_parser_executor::set_log_level(const std::vector<std::string>& args)
{
  constexpr std::string_view set_log_usage = "use: set-log <log_level_number_0-4>.";
  if(args.size() > 1)
  {
    std::cout << "Invalid syntax: Too many parameters. For more details, use the help command." << std::endl;
    return true;
  }

  if (args.empty())
  {
    std::cout << "Invalid syntax: no argument, " << set_log_usage << std::endl;
    return true;
  }

  uint16_t l = 0;
  if(epee::string_tools::get_xtype_from_string(l, args[0]))
  {
    if(4 < l)
    {
      std::cout << "Invalid syntax: Wrong number range, " << set_log_usage << std::endl;
      return true;
    }
    return m_executor.set_log_level(l);
  }

  std::cout << "Invalid syntax: Wrong number, " << set_log_usage << std::endl;
  return true;
}

bool t_command_parser_executor::print_height(const std::vector<std::string>& args)
{
  if (!args.empty()) {
    std::cout << "Invalid syntax: No parameters expected. For more details, use the help command." << std::endl;
    return true;
  }

  return m_executor.print_height();
}

bool t_command_parser_executor::print_block(const std::vector<std::string>& args)
{
  bool include_hex = false;

  // Assumes that optional flags come after mandatory argument <transaction_hash>
  for (unsigned int i = 1; i < args.size(); ++i) {
    if (args[i] == "+hex")
      include_hex = true;
    else
    {
      std::cout << "Invalid syntax: Unexpected parameter: " << args[i] << ". For more details, use the help command." << std::endl;
      return true;
    }
  }
  if (args.empty())
  {
    std::cout << "Invalid syntax: At least one parameter expected. For more details, use the help command." << std::endl;
    return true;
  }

  const std::string& arg = args.front();
  try
  {
    uint64_t height = boost::lexical_cast<uint64_t>(arg);
    return m_executor.print_block_by_height(height, include_hex);
  }
  catch (const boost::bad_lexical_cast&)
  {
    crypto::hash block_hash;
    if (parse_hash256(arg, block_hash))
    {
      return m_executor.print_block_by_hash(block_hash, include_hex);
    }
  }

  return true;
}

bool t_command_parser_executor::print_transaction(const std::vector<std::string>& args)
{
  bool include_metadata = false;
  bool include_hex = false;
  bool include_json = false;

  // Assumes that optional flags come after mandatory argument <transaction_hash>
  for (unsigned int i = 1; i < args.size(); ++i) {
    if (args[i] == "+meta")
      include_metadata = true;
    else if (args[i] == "+hex")
      include_hex = true;
    else if (args[i] == "+json")
      include_json = true;
    else
    {
      std::cout << "Invalid syntax: Unexpected parameter: " << args[i] << ". For more details, use the help command." << std::endl;
      return true;
    }
  }
  if (args.empty())
  {
    std::cout << "Invalid syntax: At least one parameter expected. For more details, use the help command." << std::endl;
    return true;
  }

  const std::string& str_hash = args.front();
  crypto::hash tx_hash;
  if (parse_hash256(str_hash, tx_hash))
  {
    m_executor.print_transaction(tx_hash, include_metadata, include_hex, include_json);
  }

  return true;
}

bool t_command_parser_executor::is_key_image_spent(const std::vector<std::string>& args)
{
  if (args.empty())
  {
    std::cout << "Invalid syntax: At least one parameter expected. For more details, use the help command." << std::endl;
    return true;
  }

  const std::string& str = args.front();
  crypto::key_image ki;
  crypto::hash hash;
  if (parse_hash256(str, hash))
  {
    memcpy(&ki, &hash, sizeof(ki));
    m_executor.is_key_image_spent(ki);
  }

  return true;
}

bool t_command_parser_executor::print_transaction_pool_long(const std::vector<std::string>& args)
{
  if (!args.empty()) {
    std::cout << "Invalid syntax: No parameters expected. For more details, use the help command." << std::endl;
    return true;
  }

  return m_executor.print_transaction_pool_long();
}

bool t_command_parser_executor::print_transaction_pool_short(const std::vector<std::string>& args)
{
  if (!args.empty()) {
    std::cout << "Invalid syntax: No parameters expected. For more details, use the help command." << std::endl;
    return true;
  }

  return m_executor.print_transaction_pool_short();
}

bool t_command_parser_executor::print_transaction_pool_stats(const std::vector<std::string>& args)
{
  if (!args.empty()) {
    std::cout << "Invalid syntax: No parameters expected. For more details, use the help command." << std::endl;
    return true;
  }

  return m_executor.print_transaction_pool_stats();
}

bool t_command_parser_executor::start_mining(const std::vector<std::string>& args)
{
  if(!args.size())
  {
    std::cout << "Invalid syntax: At least one parameter expected. For more details, use the help command." << std::endl;
    return true;
  }

  cryptonote::address_parse_info info;
  cryptonote::network_type nettype = cryptonote::MAINNET;
  if(!cryptonote::get_account_address_from_str(info, cryptonote::MAINNET, args.front()))
  {
    if(!cryptonote::get_account_address_from_str(info, cryptonote::TESTNET, args.front()))
    {
        std::string address_str;
        if(!cryptonote::get_account_address_from_str(info, cryptonote::MAINNET, address_str))
        {
          if(!cryptonote::get_account_address_from_str(info, cryptonote::TESTNET, address_str))
          {
            std::cout << "Invalid syntax: Target account address has wrong format. For more details, use the help command." << std::endl;
            return true;
          }
          else
          {
            nettype = cryptonote::TESTNET;
          }
        }
    }
    else
    {
      nettype = cryptonote::TESTNET;
    }
  }
  if (info.is_subaddress)
  {
    tools::fail_msg_writer() << "subaddress for mining reward is not yet supported!" << std::endl;
    return true;
  }
  if(nettype != cryptonote::MAINNET)
    std::cout << "Mining to a testnet address, make sure this is intentional!" << std::endl;
  uint64_t threads_count = 1;
  if(args.size() > 4)
  {
    std::cout << "Invalid syntax: Too many parameters. For more details, use the help command." << std::endl;
    return true;
  }

  if(args.size() >= 2)
  {
    bool ok = epee::string_tools::get_xtype_from_string(threads_count, args[1]);
    threads_count = (ok && 0 < threads_count) ? threads_count : 1;
  }

  m_executor.start_mining(info.address, threads_count, nettype);

  return true;
}

bool t_command_parser_executor::stop_mining(const std::vector<std::string>& args)
{
  if (!args.empty()) {
    std::cout << "Invalid syntax: No parameters expected. For more details, use the help command." << std::endl;
    return true;
  }

  return m_executor.stop_mining();
}

bool t_command_parser_executor::mining_status(const std::vector<std::string>& args)
{
  return m_executor.mining_status();
}

bool t_command_parser_executor::stop_daemon(const std::vector<std::string>& args)
{
  if (!args.empty()) {
    std::cout << "Invalid syntax: No parameters expected. For more details, use the help command." << std::endl;
    return true;
  }

  return m_executor.stop_daemon();
}

bool t_command_parser_executor::out_peers(const std::vector<std::string>& args)
{
	bool set = false;
	uint32_t limit = 0;
	try {
		if (!args.empty())
		{
			limit = std::stoi(args[0]);
			set = true;
		}
	}

	catch(const std::exception& ex) {
		_erro("stoi exception");
		std::cout << "Invalid syntax: Failed to parse number. For more details, use the help command." << std::endl;
		return true;
	}

	return m_executor.out_peers(set, limit);
}

bool t_command_parser_executor::in_peers(const std::vector<std::string>& args)
{
	bool set = false;
	uint32_t limit = 0;
	try {
		if (!args.empty())
		{
			limit = std::stoi(args[0]);
			set = true;
		}
	}

	catch(const std::exception& ex) {
		_erro("stoi exception");
		std::cout << "Invalid syntax: Failed to parse number." << std::endl;
		return true;
	}

	return m_executor.in_peers(set, limit);
}

bool t_command_parser_executor::show_bans(const std::vector<std::string>& args)
{
  if (!args.empty()) {
    std::cout << "Invalid syntax: No parameters expected. For more details, use the help command." << std::endl;
    return true;
  }

  return m_executor.print_bans();
}

bool t_command_parser_executor::ban(const std::vector<std::string>& args)
{
  if (args.size() != 1 && args.size() != 2) {
    std::cout << "Invalid syntax: Expects one or two parameters. For more details, use the help command." << std::endl;
    return true;
  }
  std::string ip = args[0];
  time_t seconds = P2P_IP_BLOCKTIME;
  if (args.size() > 1)
  {
    try
    {
      seconds = std::stoi(args[1]);
    }
    catch (const std::exception &e)
    {
      std::cout << "Invalid syntax: Failed to parse seconds. For more details, use the help command." << std::endl;
      return true;
    }
    if (seconds == 0)
    {
      std::cout << "Seconds must be greater than 0." << std::endl;
      return true;
    }
  }
  return m_executor.ban(ip, seconds);
}

bool t_command_parser_executor::unban(const std::vector<std::string>& args)
{
  if (args.size() != 1) {
    std::cout << "Invalid syntax: One parameter expected. For more details, use the help command." << std::endl;
    return true;
  }

  std::string ip = args[0];
  return m_executor.unban(ip);
}

bool t_command_parser_executor::banned(const std::vector<std::string>& args)
{
  if (args.size() != 1) {
    std::cout << "Invalid syntax: One parameter expected. For more details, use the help command." << std::endl;
    return true;
  }
  std::string address = args[0];
  return m_executor.banned(address);
}

bool t_command_parser_executor::flush_txpool(const std::vector<std::string>& args)
{
  if (args.size() > 1) {
    std::cout << "Invalid syntax: Too many parameters. For more details, use the help command." << std::endl;
    return true;
  }

  std::string txid;
  if (args.size() == 1)
  {
    crypto::hash hash;
    if (!parse_hash256(args[0], hash))
    {
      std::cout << "Invalid syntax: Failed to parse tx id. For more details, use the help command." << std::endl;
      return true;
    }
    txid = args[0];
  }
  return m_executor.flush_txpool(txid);
}

bool t_command_parser_executor::print_coinbase_tx_sum(const std::vector<std::string>& args)
{
  if(!args.size())
  {
    std::cout << "Invalid syntax: At least one parameter expected. For more details, use the help command." << std::endl;
    return true;
  }

  uint64_t height = 0;
  uint64_t count = 0;
  if(!epee::string_tools::get_xtype_from_string(height, args[0]))
  {
    std::cout << "Invalid syntax: Wrong starter block height parameter. For more details, use the help command." << std::endl;
    return true;
  }
  if(args.size() >1 && !epee::string_tools::get_xtype_from_string(count, args[1]))
  {
    std::cout << "wrong count parameter" << std::endl;
    return true;
  }

  return m_executor.print_coinbase_tx_sum(height, count);
}

bool t_command_parser_executor::alt_chain_info(const std::vector<std::string>& args)
{
  if(args.size() > 1)
  {
    std::cout << "Invalid syntax: Too many parameters. For more details, use the help command." << std::endl;
    return true;
  }

  std::string tip;
  size_t above = 0;
  uint64_t last_blocks = 0;
  if (args.size() == 1)
  {
    if (args[0].size() > 0 && args[0][0] == '>')
    {
      if (!epee::string_tools::get_xtype_from_string(above, args[0].c_str() + 1))
      {
        std::cout << "Invalid syntax: Invalid above parameter. For more details, use the help command." << std::endl;
        return true;
      }
    }
    else if (args[0].size() > 0 && args[0][0] == '-')
    {
      if (!epee::string_tools::get_xtype_from_string(last_blocks, args[0].c_str() + 1))
      {
        std::cout << "Invalid syntax: Invalid last_blocks parameter. For more details, use the help command." << std::endl;
        return true;
      }
    }
    else
    {
      tip = args[0];
    }
  }

  return m_executor.alt_chain_info(tip, above, last_blocks);
}

bool t_command_parser_executor::print_blockchain_dynamic_stats(const std::vector<std::string>& args)
{
  if(args.size() != 1)
  {
    std::cout << "Invalid syntax: One parameter expected. For more details, use the help command." << std::endl;
    return true;
  }

  uint64_t nblocks = 0;
  if(!epee::string_tools::get_xtype_from_string(nblocks, args[0]) || nblocks == 0)
  {
    std::cout << "Invalid syntax: Wrong number of blocks. For more details, use the help command." << std::endl;
    return true;
  }

  return m_executor.print_blockchain_dynamic_stats(nblocks);
}

bool t_command_parser_executor::relay_tx(const std::vector<std::string>& args)
{
  if (args.size() != 1)
  {
    std::cout << "Invalid syntax: One parameter expected. For more details, use the help command." << std::endl;
    return true;
  }

  std::string txid;
  crypto::hash hash;
  if (!parse_hash256(args[0], hash))
  {
    std::cout << "Invalid syntax: Failed to parse tx id. For more details, use the help command." << std::endl;
    return true;
  }
  txid = args[0];
  return m_executor.relay_tx(txid);
}

bool t_command_parser_executor::sync_info(const std::vector<std::string>& args)
{
  if (args.size() != 0) {
    std::cout << "Invalid syntax: No parameters expected. For more details, use the help command." << std::endl;
    return true;
  }

  return m_executor.sync_info();
}

bool t_command_parser_executor::pop_blocks(const std::vector<std::string>& args)
{
  if (args.size() != 1)
  {
    std::cout << "Invalid syntax: One parameter expected. For more details, use the help command." << std::endl;
    return true;
  }

  try
  {
    uint64_t nblocks = boost::lexical_cast<uint64_t>(args[0]);
    if (nblocks < 1)
    {
      std::cout << "Invalid syntax: Number of blocks must be greater than 0. For more details, use the help command." << std::endl;
      return true;
    }
    return m_executor.pop_blocks(nblocks);
  }
  catch (const boost::bad_lexical_cast&)
  {
    std::cout << "Invalid syntax: Number of blocks must be a number greater than 0. For more details, use the help command." << std::endl;
  }
  return true;
}

bool t_command_parser_executor::version(const std::vector<std::string>& args)
{
  return m_executor.version();
}

bool t_command_parser_executor::flush_cache(const std::vector<std::string>& args)
{
  bool bad_txs = false, bad_blocks = false;
  std::string arg;

  if (args.empty())
    goto show_list;

  for (size_t i = 0; i < args.size(); ++i)
  {
    arg = args[i];
    if (arg == "bad-txs")
      bad_txs = true;
    else if (arg == "bad-blocks")
      bad_blocks = true;
    else
      goto show_list;
  }
  return m_executor.flush_cache(bad_txs, bad_blocks);

show_list:
  std::cout << "Invalid cache type: " << arg << std::endl;
  std::cout << "Cache types: bad-txs bad-blocks" << std::endl;
  return true;
}

} // namespace daemonize
