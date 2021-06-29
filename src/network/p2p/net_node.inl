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

// IP blocking adapted from Boolberry

#pragma once

#include "network/type/parse.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net.p2p"

namespace nodetool
{
  //-----------------------------------------------------------------------------------
  template<class t_callback>
  bool node_server::try_ping(basic_node_data& node_data, p2p_connection_context& context, const t_callback &cb)
  {
    if(!node_data.my_port)
      return false;

    bool address_ok = (context.m_remote_address.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id() || context.m_remote_address.get_type_id() == epee::net_utils::ipv6_network_address::get_type_id());
    CHECK_AND_ASSERT_MES(address_ok, false,
        "Only IPv4 or IPv6 addresses are supported here");

    const epee::net_utils::network_address na = context.m_remote_address;
    std::string ip;
    uint32_t ipv4_addr = 0;
    boost::asio::ip::address_v6 ipv6_addr;
    bool is_ipv4;
    if (na.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
    {
      ipv4_addr = na.as<const epee::net_utils::ipv4_network_address>().ip();
      ip = epee::string_tools::get_ip_string_from_int32(ipv4_addr);
      is_ipv4 = true;
    }
    else
    {
      ipv6_addr = na.as<const epee::net_utils::ipv6_network_address>().ip();
      ip = ipv6_addr.to_string();
      is_ipv4 = false;
    }
    network_zone& zone = m_network_zones.at(na.get_zone());

    if(!zone.m_peerlist.is_host_allowed(context.m_remote_address))
      return false;

    std::string port = epee::string_tools::num_to_string_fast(node_data.my_port);

    epee::net_utils::network_address address;
    if (is_ipv4)
    {
      address = epee::net_utils::network_address{epee::net_utils::ipv4_network_address(ipv4_addr, node_data.my_port)};
    }
    else
    {
      address = epee::net_utils::network_address{epee::net_utils::ipv6_network_address(ipv6_addr, node_data.my_port)};
    }
    peerid_type pr = node_data.peer_id;
    bool r = zone.m_net_server.connect_async(ip, port, zone.m_config.m_net_config.ping_connection_timeout, [cb, /*context,*/ address, pr, this](
      const typename net_server::t_connection_context& ping_context,
      const boost::system::error_code& ec)->bool
    {
      if(ec)
      {
        LOG_WARNING_CC(ping_context, "back ping connect failed to " << address.str());
        return false;
      }
      COMMAND_PING::request req;
      COMMAND_PING::response rsp;
      //vc2010 workaround
      /*std::string ip_ = ip;
      std::string port_=port;
      peerid_type pr_ = pr;
      auto cb_ = cb;*/

      // GCC 5.1.0 gives error with second use of uint64_t (peerid_type) variable.
      peerid_type pr_ = pr;

      network_zone& zone = m_network_zones.at(address.get_zone());

      bool inv_call_res = epee::net_utils::async_invoke_remote_command2<COMMAND_PING::response>(ping_context, COMMAND_PING::ID, req, zone.m_net_server.get_config_object(),
        [=, this](int code, const COMMAND_PING::response& rsp, p2p_connection_context& context)
      {
        if(code <= 0)
        {
          LOG_WARNING_CC(ping_context, "Failed to invoke COMMAND_PING to " << address.str() << "(" << code <<  ", " << epee::levin::get_err_descr(code) << ")");
          return;
        }

        network_zone& zone = m_network_zones.at(address.get_zone());
        if(rsp.status != PING_OK_RESPONSE_STATUS_TEXT || pr != rsp.peer_id)
        {
          LOG_WARNING_CC(ping_context, "back ping invoke wrong response \"" << rsp.status << "\" from" << address.str() << ", hsh_peer_id=" << pr_ << ", rsp.peer_id=" << peerid_to_string(rsp.peer_id));
          zone.m_net_server.get_config_object().close(ping_context.m_connection_id);
          return;
        }
        zone.m_net_server.get_config_object().close(ping_context.m_connection_id);
        cb();
      });

      if(!inv_call_res)
      {
        LOG_WARNING_CC(ping_context, "back ping invoke failed to " << address.str());
        zone.m_net_server.get_config_object().close(ping_context.m_connection_id);
        return false;
      }
      return true;
    });
    if(!r)
    {
      LOG_WARNING_CC(context, "Failed to call connect_async, network error.");
    }
    return r;
  }
}
