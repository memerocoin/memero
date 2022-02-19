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

#include "network/rpc/core_rpc_server.h"
#include "cryptonote/protocol/cryptonote_protocol_handler.h"

#include <boost/program_options.hpp>

namespace daemonize {

  using protocol_handler = cryptonote::t_cryptonote_protocol_handler;
  using node_server = nodetool::node_server;

  class t_daemon {
  public:
    cryptonote::core core = {nullptr};
    node_server p2p;
    cryptonote::core_rpc_server rpc;
    protocol_handler protocol;

    static void init_options
    (boost::program_options::options_description & option_spec)
    {
      cryptonote::core::init_options(option_spec);
      node_server::init_options(option_spec);
      cryptonote::core_rpc_server::init_options(option_spec);
    }

  private:
    void stop_p2p();
    void stop_rpc();

  public:
    t_daemon
    (
     boost::program_options::variables_map const & vm
     );

    ~t_daemon();

    bool run();
  };
}
