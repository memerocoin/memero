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

#include <memory>
#include <stdexcept>
#include <boost/algorithm/string/split.hpp>
#include "misc_log_ex.h"
#include "daemon/daemon.h"
#include "rpc/daemon_handler.h"

#include "tools/common/password.h"
#include "tools/common/util.h"
#include "cryptonote/basic/events.h"
#include "daemon/core.h"
#include "daemon/p2p.h"
#include "daemon/protocol.h"
#include "daemon/rpc.h"
#include "daemon/command_server.h"
#include "daemon/command_line_args.h"
#include "net/net_ssl.h"
#include "version.h"

using namespace epee;

#include <functional>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "daemon"

namespace daemonize {

struct t_internals {
private:
  t_protocol protocol;
public:
  t_core core;
  t_p2p p2p;
  t_rpc rpc;

  t_internals(
      boost::program_options::variables_map const & vm
    )
    : core{vm}
    , protocol{vm, core, command_line::get_arg(vm, cryptonote::arg_offline)}
    , p2p{vm, protocol}
    , rpc{vm, core, p2p, command_line::get_arg(vm, cryptonote::core_rpc_server::arg_rpc_bind_port)}
    {
      // Handle circular dependencies
      protocol.set_p2p_endpoint(p2p.get());
      core.set_protocol(protocol.get());
  }
};

void t_daemon::init_options(boost::program_options::options_description & option_spec)
{
  t_core::init_options(option_spec);
  t_p2p::init_options(option_spec);
  t_rpc::init_options(option_spec);
}

t_daemon::t_daemon(
    boost::program_options::variables_map const & vm
  )
  : mp_internals{std::make_unique<t_internals>(vm)}
{
}

t_daemon::~t_daemon() = default;

bool t_daemon::run(bool interactive)
{
  std::atomic<bool> stop(false), shutdown(false);
  std::thread stop_thread = std::thread([&stop, &shutdown, this] {
    while (!stop)
      epee::misc_utils::sleep_no_w(100);
    if (shutdown)
      this->stop_p2p();
  });
  epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){
    stop = true;
    stop_thread.join();
  });
  tools::signal_handler::install([&stop, &shutdown](int){ stop = shutdown = true; });

  try
  {
    if (!mp_internals->core.run())
      return false;

    mp_internals->rpc.run();

    std::unique_ptr<daemonize::t_command_server> rpc_commands;
    if (interactive)
    {
      rpc_commands = std::make_unique<daemonize::t_command_server>
        (0, 0, epee::net_utils::ssl_support_t::e_ssl_support_disabled, false, mp_internals->rpc.get_server());
      rpc_commands->start_handling(std::bind(&daemonize::t_daemon::stop_p2p, this));
    }

    mp_internals->p2p.run(); // blocks until p2p goes down

    if (rpc_commands)
      rpc_commands->stop_handling();

    mp_internals->rpc.stop();
    MGINFO("Node stopped.");
    return true;
  }
  catch (std::exception const & ex)
  {
    MFATAL("Uncaught exception! " << ex.what());
    return false;
  }
  catch (...)
  {
    MFATAL("Uncaught exception!");
    return false;
  }
}

void t_daemon::stop()
{
  stop_p2p();
  mp_internals->rpc.stop();
}

void t_daemon::stop_p2p()
{
  mp_internals->p2p.stop();
}

} // namespace daemonize
