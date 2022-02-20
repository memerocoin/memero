// Copyright (c) 2006-2013, Andrey N. Sabelnikov, www.sabelnikov.net
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// * Neither the name of the Andrey N. Sabelnikov nor the
// names of its contributors may be used to endorse or promote products
// derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER  BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//




#pragma once


#include "tools/epee/include/net/abstract_tcp_server2.h"
#include "http_protocol_handler.h"




namespace epee
{

  template<class t_child_class, class t_connection_context = epee::net_utils::connection_context_base>
  class http_server_impl_base: public epee::net_utils::http::i_http_server_handler<t_connection_context>
  {

  public:
    http_server_impl_base()
        : m_net_server(epee::net_utils::e_connection_type_RPC)
    {}

    explicit http_server_impl_base(boost::asio::io_service& external_io_service)
        : m_net_server(external_io_service)
    {}

    bool init(const std::string& bind_port = "0", const std::string& bind_ip = "0.0.0.0",
      const std::string& bind_ipv6_address = "::", bool use_ipv6 = false, bool require_ipv4 = true,
      std::vector<std::string> access_control_origins = std::vector<std::string>()
     )
    {

      //set self as callback handler
      m_net_server.get_config_object().m_phandler = static_cast<t_child_class*>(this);

      //here set folder for hosting reqests
      m_net_server.get_config_object().m_folder = "";

      //set access control allow origins if configured
      std::sort(access_control_origins.begin(), access_control_origins.end());
      m_net_server.get_config_object().m_access_control_origins = std::move(access_control_origins);

      LOG_GLOBAL_INFO("Binding RPC (IPv4) on " << bind_ip << ":" << bind_port);
      if (use_ipv6)
      {
        LOG_GLOBAL_INFO("Binding RPC (IPv6) on " << bind_ipv6_address << ":" << bind_port);
      }
      bool res = m_net_server.init_server(bind_port, bind_ip, bind_port, bind_ipv6_address, use_ipv6, require_ipv4);
      if(!res)
      {
        LOG_ERROR("Failed to bind RPC server");
        return false;
      }
      return true;
    }

    bool run(size_t threads_count, bool wait = true)
    {
      //go to loop
      LOG_INFO("Run net_service loop( " << threads_count << " threads)...");
      if(!m_net_server.run_server(threads_count, wait))
      {
        LOG_ERROR("Failed to run net tcp server!");
      }

      if(wait)
        LOG_INFO("net_service loop stopped.");
      return true;
    }

    bool deinit()
    {
      return m_net_server.deinit_server();
    }

    bool wait_server_stop()
    {
      return m_net_server.wait_server_stop();
    }

    bool send_stop_signal()
    {
      m_net_server.send_stop_signal();
      return true;
    }

    int get_binded_port()
    {
      return m_net_server.get_binded_port();
    }

    long get_connections_count() const
    {
      return m_net_server.get_connections_count();
    }

  protected:
    epee::net_utils::boosted_tcp_server<net_utils::http::http_custom_handler<t_connection_context> > m_net_server;
  };
}
