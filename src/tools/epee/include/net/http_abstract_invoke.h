
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

#include "http_server_handlers_map2.h"

#include "tools/epee/include/storages/portable_storage_template_helper.h"

// https://www.boost.org/doc/libs/1_77_0/libs/beast/doc/html/beast/quick_start/http_client.html

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>


namespace epee
{
  namespace net_utils
  {
    std::optional<std::string> beast_http
    (
     const std::string host
     , const std::string port
     , const std::string uri
     , const std::string request_body
     );
     
    template<class t_request, class t_response, class t_transport>
    bool invoke_http_json
    (
     const std::string_view uri
     , const t_request& request_struct
     , t_response& result_struct
     , t_transport& transport
     , std::chrono::milliseconds timeout = std::chrono::seconds(15)
     , const std::string_view method = "POST"
     )
    {
      std::string req_param;
      if(!serialization::store_t_to_json(request_struct, req_param))
        return false;

      http::fields_list additional_params;
      additional_params.push_back(std::make_pair("Content-Type","application/json; charset=utf-8"));

      const http::http_response_info* pri = NULL;
      if(!transport.invoke(uri, method, req_param, timeout, std::addressof(pri), std::move(additional_params)))
        {
          LOG_PRINT_L1("Failed to invoke http request to  " << uri);
          return false;
        }

      const std::string host = "localhost";
      const std::string port = "45679";
      const std::string target{uri};
      const int version = 11;

      namespace beast = boost::beast;     // from <boost/beast.hpp>
      namespace http = beast::http;       // from <boost/beast/http.hpp>
      namespace net = boost::asio;        // from <boost/asio.hpp>
      using tcp = net::ip::tcp;           // from <boost/asio/ip/tcp.hpp>

      net::io_context ioc;

      // These objects perform our I/O
      tcp::resolver resolver(ioc);
      beast::tcp_stream stream(ioc);

      // // Look up the domain name
      auto const results = resolver.resolve(host, port);

      // Make the connection on the IP address we get from a lookup
      stream.connect(results);

      // // Set up an HTTP GET request message
      http::request<http::string_body> req{http::verb::post, target, version};
      req.body() = req_param;

      req.set(http::field::host, host);
      req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
      req.set(http::field::content_type,"application/json; charset=utf-8");
      // req.set(http::field::content_length,req_param.length());
      req.set(http::field::content_length, std::to_string(req_param.size()));
      // req.set("Content-Length", std::to_string(req_param.size()));

      LOG_VERBOSE("Beast REQ:");
      LOG_VERBOSE(req);


      // Send the HTTP request to the remote host
      http::write(stream, req);

      // This buffer is used for reading and must be persisted
      beast::flat_buffer buffer;

      // Declare a container to hold the response
      http::response<http::dynamic_body> res;

      // Receive the HTTP response
      http::read(stream, buffer, res);

      // Write the message to standard out
      LOG_VERBOSE("Beast RESPONSE");
      LOG_VERBOSE(res);

      // Gracefully close the socket
      beast::error_code ec;
      stream.socket().shutdown(tcp::socket::shutdown_both, ec);

      // not_connected happens sometimes
      // so don't
      //
      if(ec && ec != beast::errc::not_connected) {
        LOG_PRINT_L1("Failed to invoke http request to  " << uri << ", not connected");
      }

      const std::string m_body = boost::beast::buffers_to_string(res.body().data());

      return serialization::load_t_from_json(result_struct, m_body);
    }



    template<class t_request, class t_response, class t_transport>
    bool invoke_http_bin
    (
     const std::string_view uri
     , const t_request& out_struct
     , t_response& result_struct
     , t_transport& transport
     , std::chrono::milliseconds timeout = std::chrono::seconds(15)
     , const std::string_view method = "POST"
     )
    {
      std::string req_param;
      if(!serialization::store_t_to_binary(out_struct, req_param))
        return false;

      const http::http_response_info* pri = NULL;
      if(!transport.invoke(uri, method, req_param, timeout, std::addressof(pri)))
        {
          LOG_PRINT_L1("Failed to invoke http request to  " << uri);
          return false;
        }

      if(!pri)
        {
          LOG_PRINT_L1("Failed to invoke http request to  " << uri << ", internal error (null response ptr)");
          return false;
        }

      if(pri->m_response_code != 200)
        {
          LOG_PRINT_L1("Failed to invoke http request to  " << uri << ", wrong response code: " << pri->m_response_code);
          return false;
        }

      return serialization::load_t_from_binary(result_struct, epee::string_tools::string_to_blob(pri->m_body));
    }

    template<class t_request, class t_response, class t_transport>
    bool invoke_http_json_rpc
    (
     const std::string_view uri
     , std::string method_name
     , const t_request& out_struct
     , t_response& result_struct
     , t_transport& transport
     , std::chrono::milliseconds timeout = std::chrono::seconds(15)
     , const std::string_view http_method = "POST"
     , const std::string& req_id = "0"
     )
    {
      epee::json_rpc::error error_struct;
      epee::json_rpc::request<t_request> req_t = AUTO_VAL_INIT(req_t);
      req_t.jsonrpc = "2.0";
      req_t.id = req_id;
      req_t.method = std::move(method_name);
      req_t.params = out_struct;
      epee::json_rpc::response<t_response, epee::json_rpc::error> resp_t = AUTO_VAL_INIT(resp_t);
      if(!epee::net_utils::invoke_http_json(uri, req_t, resp_t, transport, timeout, http_method))
        {
          error_struct = {};
          return false;
        }
      if(resp_t.error.code || resp_t.error.message.size())
        {
          error_struct = resp_t.error;
          LOG_ERROR("RPC call of \"" << req_t.method << "\" returned error: " << resp_t.error.code << ", message: " << resp_t.error.message);
          return false;
        }
      result_struct = resp_t.result;
      return true;
    }
  }
}
