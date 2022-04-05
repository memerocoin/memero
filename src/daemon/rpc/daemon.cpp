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

#include "beast.hpp"

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

  const std::string rpc_description =
    "Lolnero daemon RPC server";

  const std::string beast_rpc_description =
    "Lolnero Beast daemon RPC server";

  const std::string p2p_description =
    "Lolnero daemon P2P server";

  void deinit_msg(const std::string_view x) {
    LOG_INFO("Deinitializing " + std::string(x) + " ...");
  }

  void deinit_done_msg(const std::string_view x) {
    LOG_INFO(std::string(x) + " deinitialized");
  }

  void deinit_error_msg(const std::string_view x) {
    LOG_ERROR("Failed to deinitialize " + std::string(x) + " ...");
  }

  t_daemon::~t_daemon()
  {
    deinit_msg(protocol_str);
    try {
      protocol.deinit();
      protocol.set_p2p_endpoint(nullptr);
      deinit_done_msg(protocol_str);
    } catch (...) {
      deinit_error_msg(protocol_str);
    }

    deinit_msg(p2p_str);
    try {
      p2p.deinit();
      deinit_done_msg(p2p_str);
    } catch (...) {
      deinit_error_msg(p2p_str);
    }

    deinit_msg(core_str);
    try {
      core.deinit();
      core.set_cryptonote_protocol(nullptr);
      deinit_done_msg(core_str);
    } catch (...) {
      deinit_error_msg(core_str);
    }

  }

  void init_msg(const std::string_view x) {
    LOG_INFO("Initializing " + std::string(x) + " ...");
  }

  void init_done_msg(const std::string_view x) {
    LOG_INFO(std::string(x) + " initialized");
  }

  void init_report(const bool r, const std::string_view x) {
    LOG_ERROR_AND_THROW_UNLESS
      (
       r
       , "Failed to initialize "
       + std::string(x)
       );

    init_done_msg(x);
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
      , &p2p
      , command_line::get_arg(vm, cryptonote::arg_offline)
    }
  {
    core.set_cryptonote_protocol(&protocol);

    init_msg(p2p_str);
    init_report(p2p.init(vm), p2p_str);

    const auto maybe_rpc_address = cryptonote::rpc_server::parse_args(vm);
    if (maybe_rpc_address) {
      const auto [rpc_ip, rpc_port] = *maybe_rpc_address;

      const auto rpc_ip_str = command_line::get_arg
        (
         vm 
         , cryptonote::rpc_server::arg_rpc_bind_ip
         );

      m_rpc_address = {{rpc_ip, rpc_port, rpc_ip_str}};
    }

    init_msg(protocol_str);
    init_report(protocol.init(vm), protocol_str);

    init_msg(core_str);
    init_report(core.init(vm), core_str);
  }


  bool t_daemon::run()
  {
    try
      {
        tools::signal_handler_install([this](int type) {
          LOG_INFO("Daemon interrupted with signal: " + std::to_string(type));

          LOG_INFO
            ("Stopping " + p2p_description + " ...");
          p2p.send_stop_signal();
        });


        boost::asio::io_context ioc{1};

        if (!m_rpc_address) return false;

        const auto [rpc_ip, rpc_port, rpc_ip_str] = *m_rpc_address;

        LOG_GLOBAL
          (
           "Starting "
           + beast_rpc_description
           + " on "
           + rpc_ip_str
           + ":"
           + std::to_string(rpc_port)
           + " ..."
           );

        std::thread beast_thread([&]() {
          const auto [rpc_ip, rpc_port, rpc_ip_str] = *m_rpc_address;
          cryptonote::start_beast
            (
             rpc_ip_str
             , rpc_port
             , ioc
             , rpc
             );
        });
        LOG_INFO(beast_rpc_description + " started");

        // blocks until p2p goes down
        LOG_GLOBAL("Starting " + p2p_description + " ...");
        p2p.run();
        LOG_GLOBAL(p2p_description + " stopped");

        // stop everything

        LOG_INFO("Stopping " + beast_rpc_description + " ...");
        ioc.stop();
        beast_thread.join();
        LOG_GLOBAL(beast_rpc_description + " stopped");

        protocol.stop();
        core.stop();

        return true;
      }
    catch (std::exception const & ex)
      {
        LOG_FATAL("Uncaught exception! " + std::string(ex.what()));
        return false;
      }
    catch (...)
      {
        LOG_FATAL("Uncaught exception!");
        return false;
      }
  }

  void t_daemon::init_options
  (boost::program_options::options_description & xs)
  {
    cryptonote::core::init_options(xs);
    nodetool::node_server::init_options(xs);

    command_line::add_arg
      (
       xs
       , cryptonote::rpc_server::arg_rpc_bind_ip
       );

    command_line::add_arg
      (
       xs
       , cryptonote::rpc_server::arg_rpc_bind_port
       );
  }

} // namespace daemonize
