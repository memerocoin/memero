/*

Copyright 2021 fuwa

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.


Parts of this file are originally 
Copyright (c) 2014-2020, The Monero Project

see: etc/other-licenses/monero/LICENSE


Parts of this file are originally 
copyright (c) 2012-2013 The Cryptonote developers

*/

#include "command_server.h"
#include "daemon_common.hpp"

#include "daemon/rpc/command_line_args.h"

#include "network/rpc/rpc_args.h"
#include "network/rpc/core_rpc_server.h"

#include "config/version/version.hpp"

namespace po = boost::program_options;

void print_usage(const char main[]) {
  std::cout
    << "Usage: "
    << std::string{main}
    << " <command>"
    << std::endl
    << std::endl
    ;
}

void print_help(const char main[], const po::options_description xs) {
  print_usage(main);
  std::cout << xs << std::endl;
}

int main(int argc, char const * argv[])
{
  tools::on_startup();

  po::options_description all_options("All");
  po::options_description hidden_options("Hidden");
  po::options_description visible_options("Options");
  po::positional_options_description positional_options;

  command_line::add_arg(visible_options, command_line::arg_help);
  command_line::add_arg(visible_options, command_line::arg_version);

  const cryptonote::rpc_args::descriptors arg{};
  command_line::add_arg
    (
     visible_options
     , arg.rpc_bind_ip
     );

  command_line::add_arg
    (
     visible_options
     , cryptonote::rpc_server::arg_rpc_bind_port
     );


  command_line::add_arg(hidden_options, daemon_args::arg_command);
      

  all_options.add(visible_options);
  all_options.add(hidden_options);

  // -1 for unlimited arguments
  positional_options.add(daemon_args::arg_command.name, -1); 

  po::variables_map vm;
  const bool arg_parsed = command_line::handle_error_helper
    (
     visible_options
     , [&]()
     {
       boost::program_options::store
         (
          boost::program_options::command_line_parser(argc, argv)
          .options(all_options).positional(positional_options).run()
          , vm
          );

       return true;
     }
     );

  if (!arg_parsed) return 1;

  if (command_line::get_arg(vm, command_line::arg_help))
    {
      daemon_common::show_version();
      print_help(argv[0], visible_options);
      return 0;
    }

  if (command_line::get_arg(vm, command_line::arg_version))
    {
      daemon_common::show_version();
      return 0;
    }

  po::notify(vm);

  const auto command =
    command_line::get_arg(vm, daemon_args::arg_command);

  if (!command.size()) {
    print_usage(argv[0]);
    return 1;
  }

  const auto rpc_ip_str = command_line::get_arg(vm, arg.rpc_bind_ip);
  const auto rpc_port_str = command_line::get_arg
    (
     vm
     , cryptonote::rpc_server::arg_rpc_bind_port
     );

  uint32_t rpc_ip;
  uint16_t rpc_port;
  {
    using namespace epee::string_tools;
    if (!get_ip_int32_from_string(rpc_ip, rpc_ip_str))
      {
        std::cerr << "Invalid IP: " << rpc_ip_str << std::endl;
        return 1;
      }
    if (!get_xtype_from_string(rpc_port, rpc_port_str))
      {
        std::cerr << "Invalid port: " << rpc_port_str << std::endl;
        return 1;
      }
  }

  try {

    const auto ssl_options =
      epee::net_utils::ssl_support_t::e_ssl_support_disabled;

    daemonize::t_command_server
      rpc_commands{rpc_ip, rpc_port, std::move(ssl_options)};

    if (rpc_commands.process_command_vec(command))
      {
        return 0;
      }
    else
      {
        std::cerr
          << "Unknown command: "
          << command.front()
          << std::endl
          ;
        return 1;
      }
  }
  catch (std::exception const & ex)
    {
      LOG_ERROR("Exception in main! " << ex.what());
    }
  catch (...)
    {
      LOG_ERROR("Exception in main!");
    }
  return 1;
}
