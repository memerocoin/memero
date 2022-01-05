// Copyright (c) 2017-2020, The Monero Project
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

#pragma once

#include "network/rpc/core_rpc_server_commands_defs.h"
#include "tools/epee/include/net/http_abstract_invoke.h"

#include "wallet/logic/type/typedef.hpp"
#include "wallet/logic/type/wallet.hpp"

#include <mutex>

namespace tools
{

  namespace rpc {
    using namespace cryptonote;
    COMMAND_RPC_GET_OUTPUTS_BIN::outkey parse_tx_output_result(COMMAND_RPC_GET_OUTPUTS::outkey x);
  }


  class RPC_Client
  {
  public:
    RPC_Client();

    void set_daemon(const std::string host, const std::string port);

    void set_offline(bool offline) { m_offline = offline; }

    std::optional<std::string> get_height(uint64_t &height) const;
    std::optional<std::string> get_target_height(uint64_t &height) const;
    bool get_rct_distribution(uint64_t &start_height, std::vector<uint64_t> &distribution) const;
    void get_tx_outputs
    (
     const std::vector<size_t> selected_transfers
     , const wallet::logic::type::wallet::transfer_container_span m_transfers
     , const size_t fake_outputs_count
     , std::vector<std::vector<wallet::logic::type::get_tx_outputs_entry>> &outs
     , std::vector<uint64_t> &rct_offsets
     ) const;

    template<class t_request, class t_response>
    bool invoke_http_json
    (const std::string_view uri, const t_request& req, t_response& res) const
    {
      if (m_offline) return false;
      return epee::net_utils::invoke_http_json
        (m_host, m_port, uri, req, res);
    }

    template<class t_request, class t_response>
    bool invoke_http_json_rpc
    (const std::string& method_name, const t_request& req, t_response& res) const
    {
      if (m_offline) return false;
      return epee::net_utils::invoke_http_json_rpc
        (m_host, m_port, "/json_rpc", method_name, req, res);
    }

  private:
    std::string m_host = "localhost";
    std::string m_port = "45679";
  
    bool m_offline;

    bool tx_add_fake_output
    (
     std::vector<std::vector<wallet::logic::type::get_tx_outputs_entry>> &outs
     , uint64_t global_index
     , const crypto::public_key& tx_public_key
     , const crypto::ec_point& mask
     , uint64_t real_index
     , bool unlocked
     ) const;
  };

}
