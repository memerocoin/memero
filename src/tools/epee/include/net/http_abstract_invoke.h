
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

#include "jsonrpc_structs.h"

#include "tools/epee/include/storages/portable_storage_template_helper.h"

namespace epee
{
  namespace net_utils
  {
    std::optional<std::string> beast_http_json
    (
     const std::string host
     , const std::string port
     , const std::string uri
     , const std::string request_body
     );

    template<class t_request, class t_response>
    bool invoke_http_json
    (
     const std::string host
     , const std::string port 
     , const std::string_view uri
     , const t_request& request_struct
     , t_response& result_struct
     )
    {
      std::string req_param;
      if(!serialization::store_t_to_json(request_struct, req_param))
        return false;

      const std::optional<std::string> response =
        beast_http_json(host, port, std::string(uri), req_param);

      if (!response) {
        return false;
      }

      return serialization::load_t_from_json(result_struct, *response);
    }

    template<class t_request, class t_response>
    bool invoke_http_json_rpc
    (
     const std::string host
     , const std::string port 
     , const std::string_view uri
     , const std::string method_name
     , const t_request& request_struct
     , t_response& result_struct
     )
    {
      const std::string req_id = "0";
      epee::json_rpc::error error_struct;
      epee::json_rpc::request<t_request> req_t{};
      req_t.jsonrpc = "2.0";
      req_t.id = req_id;
      req_t.method = std::move(method_name);
      req_t.params = request_struct;
      epee::json_rpc::response<t_response, epee::json_rpc::error> resp_t{};

      if(!epee::net_utils::invoke_http_json
         (host, port, uri, req_t, resp_t))
        {
          error_struct = {};
          return false;
        }
      if(resp_t.error.code || resp_t.error.message.size())
        {
          error_struct = resp_t.error;
          LOG_ERROR
            (
             "RPC call of \""
             + req_t.method
             + "\" returned error: "
             + std::to_string(resp_t.error.code)
             + ", message: "
             + resp_t.error.message
             );
          return false;
        }
      result_struct = resp_t.result;
      return true;
    }

  }
}
