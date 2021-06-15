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

#include "node_rpc_proxy.h"
#include "network/rpc/core_rpc_server_commands_defs.h"
#include "tools/epee/include/storages/http_abstract_invoke.h"

#define RETURN_ON_RPC_RESPONSE_ERROR(r, error, res, method) \
  do { \
    CHECK_AND_ASSERT_MES(error.code == 0, error.message, error.message); \
    CHECK_AND_ASSERT_MES(r, std::string("Failed to connect to daemon"), "Failed to connect to daemon"); \
    /* empty string -> not connection */ \
    CHECK_AND_ASSERT_MES(!res.status.empty(), res.status, "No connection to daemon"); \
    CHECK_AND_ASSERT_MES(res.status != CORE_RPC_STATUS_BUSY, res.status, "Daemon busy"); \
    CHECK_AND_ASSERT_MES(res.status == CORE_RPC_STATUS_OK, res.status, "Error calling " + std::string(method) + " daemon RPC"); \
  } while(0)

using namespace epee;

namespace tools
{

static const std::chrono::seconds rpc_timeout = std::chrono::minutes(3) + std::chrono::seconds(30);

NodeRPCProxy::NodeRPCProxy(epee::net_utils::http::abstract_http_client &http_client, std::recursive_mutex &mutex)
  : m_http_client(http_client)
  , m_daemon_rpc_mutex(mutex)
  , m_offline(false)
{
  invalidate();
}

void NodeRPCProxy::invalidate()
{
  m_height = 0;
  for (size_t n = 0; n < 256; ++n)
    m_earliest_height[n] = 0;
  m_rpc_version = 0;
  m_target_height = 0;
  m_get_info_time = 0;
  m_height_time = 0;
}

void NodeRPCProxy::set_height(uint64_t h)
{
  m_height = h;
  m_height_time = time(NULL);
}

std::optional<std::string> NodeRPCProxy::get_info()
{
  if (m_offline)
    return std::optional<std::string>("offline");
  const time_t now = time(NULL);
  if (now >= m_get_info_time + 30) // re-cache every 30 seconds
  {
    cryptonote::COMMAND_RPC_GET_INFO::request req_t = AUTO_VAL_INIT(req_t);
    cryptonote::COMMAND_RPC_GET_INFO::response resp_t = AUTO_VAL_INIT(resp_t);

    {
      const std::lock_guard<std::recursive_mutex> lock{m_daemon_rpc_mutex};
      bool r = epee::net_utils::invoke_http_json_rpc("/json_rpc", "get_info", req_t, resp_t, m_http_client, rpc_timeout);
      RETURN_ON_RPC_RESPONSE_ERROR(r, epee::json_rpc::error{}, resp_t, "get_info");
    }

    m_height = resp_t.height;
    m_target_height = resp_t.target_height;
    m_get_info_time = now;
    m_height_time = now;
  }
  return std::optional<std::string>();
}

std::optional<std::string> NodeRPCProxy::get_height(uint64_t &height)
{
  const time_t now = time(NULL);
  if (now < m_height_time + 30) // re-cache every 30 seconds
  {
    height = m_height;
    return std::optional<std::string>();
  }

  auto res = get_info();
  if (res)
    return res;
  height = m_height;
  return std::optional<std::string>();
}

std::optional<std::string> NodeRPCProxy::get_target_height(uint64_t &height)
{
  auto res = get_info();
  if (res)
    return res;
  height = m_target_height;
  return std::optional<std::string>();
}

}
