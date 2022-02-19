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

#include "daemon.h"

#include "network/p2p/net_node.h"
#include "network/rpc/core_rpc_server.h"
#include "network/rpc/rpc_args.h"

#include "cryptonote/core/cryptonote_core.h"
#include "cryptonote/protocol/cryptonote_protocol_handler.h"

#include "tools/epee/include/logging.hpp"

namespace daemonize {
  constexpr std::string_view protocol_str = "protocol";
  constexpr std::string_view core_str = "core";
  constexpr std::string_view p2p_str = "P2P";
  constexpr std::string_view rpc_str = "RPC";
  constexpr std::string_view cryptonote_str = "CryptoNote";

  t_daemon::~t_daemon()
  {
    LOG_GLOBAL_INFO("Deinitializing " << rpc_str << " ...");
    try {
      rpc.deinit();
    } catch (...) {
      LOG_ERROR("Failed to deinitialize " << rpc_str << " ...");
    }

    LOG_GLOBAL_INFO("Deinitializing " << p2p_str << " ...");
    try {
      p2p.deinit();
    } catch (...) {
      LOG_ERROR("Failed to deinitialize " << p2p_str << " ...");
    }

    LOG_GLOBAL_INFO("Deinitializing " << core_str << " ...");
    try {
      core.deinit();
      core.set_cryptonote_protocol(nullptr);
    } catch (...) {
      LOG_ERROR("Failed to deinitialize " << core_str << " ...");
    }

    LOG_GLOBAL_INFO("Deinitializing " << protocol_str << " ...");
    try {
      protocol.deinit();
      protocol.set_p2p_endpoint(nullptr);
      LOG_GLOBAL_INFO(cryptonote_str << " stopped successfully.");
    } catch (...) {
      LOG_ERROR("Failed to deinitialize " << protocol_str << " ...");
    }
  }

  t_daemon::t_daemon
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

    LOG_GLOBAL_INFO("Initializing " << protocol_str << " ...");
    LOG_ERROR_AND_THROW_UNLESS
      (
       protocol.init(vm)
       , "Failed to initialize " << protocol_str << "."
       );

    LOG_GLOBAL_INFO(protocol_str << " initialized.");



    LOG_GLOBAL_INFO("Initializing " << core_str << " ...");
    LOG_ERROR_AND_THROW_UNLESS
      (
       core.init(vm)
       , "Failed to initialize " << core_str
       );
    LOG_GLOBAL_INFO(core_str << " initialized.");


    LOG_GLOBAL_INFO("Initializing " << p2p_str << " ...");
    LOG_ERROR_AND_THROW_UNLESS
      (
       p2p.init(vm)
       , "Failed to initialize " << p2p_str << "."
       );
    LOG_GLOBAL_INFO(p2p_str << " initialized.");


    const std::string rpc_port =
      command_line::get_arg
      (
       vm
       , cryptonote::rpc_server::arg_rpc_bind_port
       );

    LOG_GLOBAL_INFO
      ("Initializing " << rpc_str << " ...");

    LOG_ERROR_AND_THROW_UNLESS
      (
       rpc.init(vm, rpc_port)
       , "Failed to initialize "
       << rpc_str
       << "."
       );

    LOG_GLOBAL_INFO(rpc_str << " initialized.");

    LOG_GLOBAL_INFO(cryptonote_str << " initialized.");
  }


  bool t_daemon::run()
  {
    std::atomic<bool> stop(false), shutdown(false);

    std::thread stop_thread = std::thread([&stop, &shutdown, this] {
      while (!stop)
        epee::misc_utils::sleep_no_w(100);
      if (shutdown)
        this->stop_p2p();
    });

    epee::misc_utils::auto_scope_leave_caller scope_exit_handler =
      epee::misc_utils::create_scope_leave_handler([&](){
        stop = true;
        stop_thread.join();
      });

    tools::signal_handler_install
      ([&stop, &shutdown](int){ stop = shutdown = true; });

    try
      {
        LOG_GLOBAL_INFO
          ("Starting " << rpc_description << " RPC server...");
        LOG_ERROR_AND_THROW_UNLESS
          (
           rpc.run(2, false)
           , "Failed to start "
           << rpc_description
           << " RPC server."
           );

        LOG_GLOBAL_INFO(rpc_description << " RPC server started.");

        // blocks until p2p goes down
        LOG_GLOBAL_INFO("Starting p2p net loop...");
        p2p.run();
        LOG_GLOBAL_INFO("p2p net loop stopped");

        stop_rpc();

        return true;
      }
    catch (std::exception const & ex)
      {
        LOG_FATAL("Uncaught exception! " << ex.what());
        return false;
      }
    catch (...)
      {
        LOG_FATAL("Uncaught exception!");
        return false;
      }
  }

  void t_daemon::stop_rpc() {
    LOG_GLOBAL_INFO
      ("Stopping " << rpc_description << " RPC server...");
    rpc.send_stop_signal();
    rpc.timed_wait_server_stop(5000);
    LOG_GLOBAL_INFO("Node stopped.");
  }

  void t_daemon::stop_p2p()
  {
    p2p.send_stop_signal();
  }

} // namespace daemonize
