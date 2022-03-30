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

#include "buffer.h"
#include "levin_base.h"

#include "tools/epee/include/misc_os_dependent.h"
#include "tools/epee/include/net/net_utils_base.h"
#include "tools/epee/include/syncobj.h"

#include "cryptonote/protocol/connection_context.h"
#include "cryptonote/basic/type/string_blob_type.hpp"
#include "network/p2p/p2p_protocol_defs.h"

#include <random>

#include <boost/uuid/uuid_generators.hpp>
#include <boost/functional/hash.hpp>
#include <boost/asio/steady_timer.hpp>

#include "config/lol.hpp"


#ifndef MIN_BYTES_WANTED
#define MIN_BYTES_WANTED	512
#endif

using namespace constant;

namespace nodetool
{
  template<class base_type>
  struct p2p_connection_context_t: base_type //t_payload_net_handler::connection_context //public epee::net_utils::connection_context_base
  {
    p2p_connection_context_t()
      : fluff_txs(),
        flush_time(std::chrono::steady_clock::time_point::max()),
        peer_id(0),
        support_flags(0),
        m_in_timedsync(false)
    {}

    static constexpr int handshake_command() noexcept { return 1001; }

    std::vector<cryptonote::string_blob> fluff_txs;
    std::chrono::steady_clock::time_point flush_time;
    peerid_type peer_id;
    uint32_t support_flags;
    bool m_in_timedsync;
    std::set<epee::net_utils::network_address> sent_addresses;
  };
}

namespace epee
{
namespace levin
{

  constexpr auto LOG_ERROR_CC = epee::net_utils::LOG_ERROR_CC;

  using t_connection_context =
    nodetool::p2p_connection_context_t
    <cryptonote::cryptonote_connection_context>;

class async_protocol_handler;

using t_connection_context =
  nodetool::p2p_connection_context_t<cryptonote::cryptonote_connection_context>;

class async_protocol_handler_config
{
  typedef std::unordered_map<boost::uuids::uuid, async_protocol_handler*, boost::hash<boost::uuids::uuid>> connections_map;
  std::recursive_mutex m_connects_lock;
  connections_map m_connects;

  void add_connection(async_protocol_handler* pc);
  void del_connection(async_protocol_handler* pc);

  async_protocol_handler* find_connection(boost::uuids::uuid connection_id) const;
  int find_and_lock_connection(boost::uuids::uuid connection_id, async_protocol_handler*& aph);

  friend class async_protocol_handler;

  levin_commands_handler<t_connection_context>* m_pcommands_handler;
  void (*m_pcommands_handler_destroy)(levin_commands_handler<t_connection_context>*);

  void delete_connections (size_t count, bool incoming);

public:
  typedef t_connection_context connection_context;
  uint64_t m_initial_max_packet_size;
  uint64_t m_max_packet_size;
  uint64_t m_invoke_timeout;

  int invoke(int command, const std::span<const uint8_t> in_buff, std::string& buff_out, boost::uuids::uuid connection_id);
  template<class callback_t>
  int invoke_async(int command, const std::span<const uint8_t> in_buff, boost::uuids::uuid connection_id, const callback_t &cb, size_t timeout = LEVIN_DEFAULT_TIMEOUT_PRECONFIGURED);

  int notify(int command, const std::span<const uint8_t> in_buff, boost::uuids::uuid connection_id);
  bool close(boost::uuids::uuid connection_id);
  bool update_connection_context(const t_connection_context& contxt);
  bool request_callback(boost::uuids::uuid connection_id);
  template<class callback_t>
  bool foreach_connection(const callback_t &cb);
  template<class callback_t>
  bool for_connection(const boost::uuids::uuid &connection_id, const callback_t &cb);
  size_t get_connections_count();
  size_t get_out_connections_count();
  size_t get_in_connections_count();
  void set_handler(levin_commands_handler<t_connection_context>* handler, void (*destroy)(levin_commands_handler<t_connection_context>*) = NULL);

  async_protocol_handler_config():m_pcommands_handler(NULL), m_pcommands_handler_destroy(NULL), m_initial_max_packet_size(LEVIN_INITIAL_MAX_PACKET_SIZE), m_max_packet_size(LEVIN_DEFAULT_MAX_PACKET_SIZE), m_invoke_timeout(LEVIN_DEFAULT_TIMEOUT_PRECONFIGURED)
  {}
  ~async_protocol_handler_config() { set_handler(NULL, NULL); }
  void del_out_connections(size_t count);
  void del_in_connections(size_t count);
};


/************************************************************************/
/*                                                                      */
/************************************************************************/
class async_protocol_handler
{
  std::string m_fragment_buffer;

  bool send_message(uint32_t command, std::span<const uint8_t> in_buff, uint32_t flags, bool expect_response);

public:
  typedef t_connection_context connection_context;
  typedef async_protocol_handler_config config_type;

  enum stream_state
  {
    stream_state_head,
    stream_state_body
  };

  std::atomic<bool> m_deletion_initiated;
  std::atomic<bool> m_protocol_released;
  std::atomic<bool> m_invoke_buf_ready;

  std::atomic<int> m_invoke_result_code;

  std::recursive_mutex m_local_inv_buff_lock;
  std::string m_local_inv_buff;

  std::recursive_mutex m_call_lock;

  std::atomic<uint32_t> m_wait_count;
  std::atomic<bool> m_close_called;
  bucket_head2 m_current_head;
  epee::net_utils::i_service_endpoint* m_pservice_endpoint;
  config_type& m_config;
  t_connection_context& m_connection_context;
  std::atomic<uint64_t> m_max_packet_size;

  epee::net_utils::buffer m_cache_in_buffer;
  stream_state m_state;

  int32_t m_oponent_protocol_ver;
  bool m_connection_initialized;

  struct invoke_response_handler_base
  {
    virtual bool handle(int res, const std::span<const uint8_t> buff, connection_context& context)=0;
    virtual bool is_timer_started() const=0;
    virtual void cancel()=0;
    virtual bool cancel_timer()=0;
    virtual void reset_timer()=0;
  };
  template <class callback_t>
  struct anvoke_handler: invoke_response_handler_base
  {
    anvoke_handler
    (
     const callback_t& cb
     , uint64_t timeout
     ,  async_protocol_handler& con
     , int command
     )
      : m_cb(cb)
      , m_con(con)
      , m_timer(con.m_pservice_endpoint->get_io_service())
      , m_timeout(timeout)
      , m_command(command)
    {
      if(m_con.start_outer_call())
      {
        LOG_DEBUG
          (
           con.get_context_ref().to_str()
           + "anvoke_handler, timeout: "
           + std::to_string(timeout)
           );
        m_timer.expires_after(std::chrono::milliseconds(timeout));
        m_timer.async_wait([&con, command, cb, timeout](const boost::system::error_code& ec)
        {
          if(ec == boost::asio::error::operation_aborted)
            return;
          LOG_INFO
            (
             con.get_context_ref().to_str()
             + "Timeout on invoke operation happened, command: "
             + std::to_string(command)
             + " timeout: "
             + std::to_string(timeout)
             );
          std::span<const uint8_t> fake;
          cb(LEVIN_ERROR_CONNECTION_TIMEDOUT, fake, con.get_context_ref());
          con.close();
          con.finish_outer_call();
        });
        m_timer_started = true;
      }
    }
    virtual ~anvoke_handler()
    {}
    callback_t m_cb;
    async_protocol_handler& m_con;
    boost::asio::steady_timer m_timer;
    bool m_timer_started = false;
    bool m_cancel_timer_called = false;
    bool m_timer_cancelled = false;
    uint64_t m_timeout;
    int m_command;
    virtual bool handle(int res, const std::span<const uint8_t> buff, typename async_protocol_handler::connection_context& context)
    {
      if(!cancel_timer())
        return false;
      m_cb(res, buff, context);
      m_con.finish_outer_call();
      return true;
    }
    virtual bool is_timer_started() const
    {
      return m_timer_started;
    }
    virtual void cancel()
    {
      if(cancel_timer())
      {
        std::span<const uint8_t> fake;
        m_cb(LEVIN_ERROR_CONNECTION_DESTROYED, fake, m_con.get_context_ref());
        m_con.finish_outer_call();
      }
    }
    virtual bool cancel_timer()
    {
      if(!m_cancel_timer_called)
      {
        m_cancel_timer_called = true;
        boost::system::error_code ignored_ec;
        m_timer_cancelled = 1 == m_timer.cancel(ignored_ec);
      }
      return m_timer_cancelled;
    }
    virtual void reset_timer()
    {
      boost::system::error_code ignored_ec;
      if (!m_cancel_timer_called && m_timer.cancel(ignored_ec) > 0)
      {
        callback_t& cb = m_cb;
        uint64_t timeout = m_timeout;
        async_protocol_handler& con = m_con;
        int command = m_command;
        m_timer.expires_after(std::chrono::milliseconds(m_timeout));
        m_timer.async_wait([&con, cb, command, timeout](const boost::system::error_code& ec)
        {
          if(ec == boost::asio::error::operation_aborted)
            return;
          LOG_INFO
            (
             con.get_context_ref().to_str()
             + "Timeout on invoke operation happened, command: "
             + std::to_string(command)
             + " timeout: "
             + std::to_string(timeout)
             );
          std::span<const uint8_t> fake;
          cb(LEVIN_ERROR_CONNECTION_TIMEDOUT, fake, con.get_context_ref());
          con.close();
          con.finish_outer_call();
        });
      }
    }
  };
  std::recursive_mutex m_invoke_response_handlers_lock;
  std::list<std::shared_ptr<invoke_response_handler_base> > m_invoke_response_handlers;

  template<class callback_t>
  bool add_invoke_response_handler(const callback_t &cb, uint64_t timeout,  async_protocol_handler& con, int command)
  {
    LOCK_RECURSIVE_MUTEX(m_invoke_response_handlers_lock);
    if (m_protocol_released)
    {
      LOG_ERROR("Adding response handler to a released object");
      return false;
    }
    std::shared_ptr<invoke_response_handler_base> handler(std::make_shared<anvoke_handler<callback_t>>(cb, timeout, con, command));
    m_invoke_response_handlers.push_back(handler);
    return handler->is_timer_started();
  }

  template<class callback_t> friend struct anvoke_handler;

public:
  async_protocol_handler(epee::net_utils::i_service_endpoint* psnd_hndlr,
    config_type& config,
    t_connection_context& conn_context):
            m_current_head(bucket_head2()),
            m_pservice_endpoint(psnd_hndlr),
            m_config(config),
            m_connection_context(conn_context),
            m_max_packet_size(config.m_initial_max_packet_size),
            m_cache_in_buffer(4 * 1024),
            m_state(stream_state_head)
  {
    m_close_called = false;
    m_deletion_initiated = false;
    m_protocol_released = false;
    m_wait_count = 0;
    m_oponent_protocol_ver = 0;
    m_connection_initialized = false;
    m_invoke_buf_ready = false;
    m_invoke_result_code = LEVIN_ERROR_CONNECTION;
  }

  virtual ~async_protocol_handler()
  {
    try
    {

    m_deletion_initiated = true;
    if(m_connection_initialized)
    {
      m_config.del_connection(this);
    }

    for (size_t i = 0; i < 60 * 1000 / 100 && 0 != m_wait_count; ++i)
    {
      epee::misc_utils::sleep_no_w(100);
    }
    if(0 != m_wait_count) {
      LOG_ERROR
        (
         "Failed to wait for operation completion. m_wait_count = "
         + std::to_string(m_wait_count)
         );
    }

    LOG_TRACE(m_connection_context.to_str() + "~async_protocol_handler()");

    }
    catch (...) { /* ignore */ }
  }

  bool start_outer_call();

  bool finish_outer_call();
  bool release_protocol();
  bool close();

  void update_connection_context(const connection_context& contxt);
  void request_callback();
  void handle_qued_callback();
  virtual bool handle_recv(const void* ptr, size_t cb);
  bool after_init_connection();

  template<class callback_t>
  bool async_invoke(int command, const std::span<const uint8_t> in_buff, const callback_t &cb, size_t timeout = LEVIN_DEFAULT_TIMEOUT_PRECONFIGURED)
  {
    epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler(
      std::bind(&async_protocol_handler::finish_outer_call, this));

    if(timeout == LEVIN_DEFAULT_TIMEOUT_PRECONFIGURED)
      timeout = m_config.m_invoke_timeout;

    int err_code = LEVIN_OK;
    do
    {
      if(m_deletion_initiated)
      {
        err_code = LEVIN_ERROR_CONNECTION_DESTROYED;
        break;
      }

      LOCK_RECURSIVE_MUTEX(m_call_lock);

      if(m_deletion_initiated)
      {
        err_code = LEVIN_ERROR_CONNECTION_DESTROYED;
        break;
      }

      m_invoke_buf_ready = false;
      {
        LOCK_RECURSIVE_MUTEX(m_invoke_response_handlers_lock);

        if (command == m_connection_context.handshake_command())
          m_max_packet_size = m_config.m_max_packet_size;

        if(!send_message(command, in_buff, LEVIN_PACKET_REQUEST, true))
        {
          LOG_ERROR_CC(m_connection_context, "Failed to do_send");
          err_code = LEVIN_ERROR_CONNECTION;
          break;
        }

        if(!add_invoke_response_handler(cb, timeout, *this, command))
        {
          err_code = LEVIN_ERROR_CONNECTION_DESTROYED;
          break;
        }
      }
    } while (false);

    if (LEVIN_OK != err_code)
    {
      // Never call callback inside critical section, that can cause deadlock
      cb(err_code, std::span<const uint8_t>(), m_connection_context);
      return false;
    }

    return true;
  }

  int invoke(int command, const std::span<const uint8_t> in_buff, std::string& buff_out)
  {
    epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler
      (std::bind(&async_protocol_handler::finish_outer_call, this));

    if(m_deletion_initiated)
      return LEVIN_ERROR_CONNECTION_DESTROYED;

    LOCK_RECURSIVE_MUTEX(m_call_lock);

    if(m_deletion_initiated)
      return LEVIN_ERROR_CONNECTION_DESTROYED;

    m_invoke_buf_ready = false;

    if (command == m_connection_context.handshake_command())
      m_max_packet_size = m_config.m_max_packet_size;

    if (!send_message(command, in_buff, LEVIN_PACKET_REQUEST, true))
    {
      LOG_ERROR_CC(m_connection_context, "Failed to send request");
      return LEVIN_ERROR_CONNECTION;
    }

    uint64_t ticks_start = epee::misc_utils::get_tick_count();
    size_t prev_size = 0;

    while(!m_invoke_buf_ready && !m_deletion_initiated && !m_protocol_released)
    {
      if(m_cache_in_buffer.size() - prev_size >= MIN_BYTES_WANTED)
      {
        prev_size = m_cache_in_buffer.size();
        ticks_start = epee::misc_utils::get_tick_count();
      }
      if(misc_utils::get_tick_count() - ticks_start > m_config.m_invoke_timeout)
      {
        LOG_WARNING
          (
           m_connection_context.to_str()
           + "invoke timeout ("
           + std::to_string(m_config.m_invoke_timeout)
           + "), closing connection "
           );
        close();
        return LEVIN_ERROR_CONNECTION_TIMEDOUT;
      }
      if(!m_pservice_endpoint->call_run_once_service_io())
        return LEVIN_ERROR_CONNECTION_DESTROYED;
    }

    if(m_deletion_initiated || m_protocol_released)
      return LEVIN_ERROR_CONNECTION_DESTROYED;

    {
      LOCK_RECURSIVE_MUTEX(m_local_inv_buff_lock);
      buff_out.swap(m_local_inv_buff);
      m_local_inv_buff.clear();
    }

    return m_invoke_result_code;
  }

  int notify(int command, const std::span<const uint8_t> in_buff);

  //------------------------------------------------------------------------------------------
  boost::uuids::uuid get_connection_id() {return m_connection_context.m_connection_id;}
  //------------------------------------------------------------------------------------------
  t_connection_context& get_context_ref() {return m_connection_context;}
};
//------------------------------------------------------------------------------------------
template<class callback_t>
int async_protocol_handler_config::invoke_async(int command, const std::span<const uint8_t> in_buff, boost::uuids::uuid connection_id, const callback_t &cb, size_t timeout)
{
  async_protocol_handler* aph;
  int r = find_and_lock_connection(connection_id, aph);
  return LEVIN_OK == r ? aph->async_invoke(command, in_buff, cb, timeout) : r;
}
//------------------------------------------------------------------------------------------
template<class callback_t>
bool async_protocol_handler_config::foreach_connection(const callback_t &cb)
{
  LOCK_RECURSIVE_MUTEX(m_connects_lock);
  for(auto& c: m_connects)
  {
    async_protocol_handler* aph = c.second;
    if(!cb(aph->get_context_ref()))
      return false;
  }
  return true;
}
//------------------------------------------------------------------------------------------
template<class callback_t>
bool async_protocol_handler_config::for_connection(const boost::uuids::uuid &connection_id, const callback_t &cb)
{
  LOCK_RECURSIVE_MUTEX(m_connects_lock);
  async_protocol_handler* aph = find_connection(connection_id);
  if (!aph)
    return false;
  if(!cb(aph->get_context_ref()))
    return false;
  return true;
}
}
}
