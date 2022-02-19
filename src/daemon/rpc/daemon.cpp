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

namespace daemonize {

  void t_daemon::init_options
  (boost::program_options::options_description & option_spec)
  {
    t_core::init_options(option_spec);
    t_p2p::init_options(option_spec);
    t_rpc::init_options(option_spec);
  }

  t_daemon::t_daemon
  (
   boost::program_options::variables_map const & vm
   )
    : mp_internals{t_internals(vm)}
  {
  }

  bool t_daemon::run(bool interactive)
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
        LOG_GLOBAL_INFO("Starting " << rpc_description << " RPC server...");
        LOG_ERROR_AND_THROW_UNLESS
          (
           mp_internals.rpc.run(2, false)
           , "Failed to start "
           << rpc_description
           << " RPC server."
           );

        LOG_GLOBAL_INFO(rpc_description << " RPC server started.");

        // blocks until p2p goes down
        LOG_GLOBAL_INFO("Starting p2p net loop...");
        mp_internals.p2p.run();
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
    mp_internals.rpc.send_stop_signal();
    mp_internals.rpc.timed_wait_server_stop(5000);
    LOG_GLOBAL_INFO("Node stopped.");
  }

  void t_daemon::stop()
  {
    stop_p2p();
    stop_rpc();
  }

  void t_daemon::stop_p2p()
  {
    mp_internals.p2p.send_stop_signal();
  }

} // namespace daemonize
