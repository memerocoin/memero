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

#pragma once

#include "daemon/rpc/core.h"
#include "daemon/rpc/p2p.h"
#include "daemon/rpc/rpc.h"

#include "network/rpc/rpc_args.h"

#include <boost/program_options.hpp>

namespace daemonize {

  using protocol_handler = cryptonote::t_cryptonote_protocol_handler;
  using node_server = nodetool::node_server;

  constexpr std::string_view rpc_description = "lolnero daemon";

  struct t_internals
  {
    cryptonote::core core = {nullptr};
    node_server p2p;
    cryptonote::core_rpc_server rpc;
    protocol_handler protocol;

    t_internals
    (
     boost::program_options::variables_map const & vm
     )
      : p2p{protocol}
      , rpc{core, p2p}
      , protocol
      {
        core
        , nullptr
        , command_line::get_arg(vm, cryptonote::arg_offline)
      }
    {
      protocol.set_p2p_endpoint(&p2p);
      core.set_cryptonote_protocol(&protocol);

      LOG_GLOBAL_INFO("Initializing Core...");

      LOG_ERROR_AND_THROW_UNLESS
      (
       core.init(vm)
       , "Failed to initialize Core"
       );
      LOG_GLOBAL_INFO("Core initialized.");


      LOG_GLOBAL_INFO("Initializing cryptonote protocol...");

      LOG_ERROR_AND_THROW_UNLESS
      (
       protocol.init(vm)
       , "Failed to initialize cryptonote protocol."
       );

      LOG_GLOBAL_INFO("Cryptonote protocol initialized.");

      LOG_GLOBAL_INFO("Initializing p2p server...");
      LOG_ERROR_AND_THROW_UNLESS
        (
         p2p.init(vm)
         , "Failed to initialize p2p server."
         );
      LOG_GLOBAL_INFO("p2p server initialized.");


      const std::string rpc_port =
        command_line::get_arg
        (
         vm
         , cryptonote::rpc_server::arg_rpc_bind_port
         );

      LOG_GLOBAL_INFO
        ("Initializing " << rpc_description << " RPC server...");

      LOG_ERROR_AND_THROW_UNLESS
        (
         rpc.init(vm, rpc_port)
         , "Failed to initialize "
         << rpc_description
         << " RPC server."
         );

    }
  };


  class t_daemon {
  public:
    static void init_options
    (boost::program_options::options_description & option_spec);

  private:
    void stop_p2p();
    void stop_rpc();
  private:
    t_internals mp_internals;
  public:
    t_daemon(
             boost::program_options::variables_map const & vm
             );

    bool run(bool interactive = false);
    void stop();
  };
}
