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

#include <random>

#include <boost/uuid/uuid_generators.hpp>
#include <boost/functional/hash.hpp>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net"

#ifndef MIN_BYTES_WANTED
#define MIN_BYTES_WANTED	512
#endif

using namespace constant;

namespace epee
{
namespace levin
{

/************************************************************************/
/*                                                                      */
/************************************************************************/
template<class t_connection_context>
class async_protocol_handler;

template<class t_connection_context>
class async_protocol_handler_config
{
  typedef std::unordered_map<boost::uuids::uuid, async_protocol_handler<t_connection_context>*, boost::hash<boost::uuids::uuid>> connections_map;
  std::recursive_mutex m_connects_lock;
  connections_map m_connects;

  void add_connection(async_protocol_handler<t_connection_context>* pc);
  void del_connection(async_protocol_handler<t_connection_context>* pc);

  async_protocol_handler<t_connection_context>* find_connection(boost::uuids::uuid connection_id) const;
  int find_and_lock_connection(boost::uuids::uuid connection_id, async_protocol_handler<t_connection_context>*& aph);

  friend class async_protocol_handler<t_connection_context>;

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
template<class t_connection_context = epee::net_utils::connection_context_base>
class async_protocol_handler
{
  std::string m_fragment_buffer;

  bool send_message(uint32_t command, std::span<const uint8_t> in_buff, uint32_t flags, bool expect_response)
  {
    const bucket_head2 head = make_header(command, in_buff.size(), flags, expect_response);
    std::span<const uint8_t> head_span = as_byte_span(head);
    const auto head_string = std::basic_string<uint8_t>(head_span.data(), head_span.size());
    const auto in_buff_string = std::basic_string<uint8_t>(in_buff.data(), in_buff.size());
    if(!m_pservice_endpoint->do_send(head_string + in_buff_string))
      return false;

    MDEBUG(m_connection_context << "LEVIN_PACKET_SENT. [len=" << head.m_cb
        << ", flags" << head.m_flags
        << ", r?=" << head.m_have_to_return_data
        <<", cmd = " << head.m_command
        << ", ver=" << head.m_protocol_version);
    return true;
  }

public:
  typedef t_connection_context connection_context;
  typedef async_protocol_handler_config<t_connection_context> config_type;

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
    anvoke_handler(const callback_t& cb, uint64_t timeout,  async_protocol_handler& con, int command)
      :m_cb(cb), m_timeout(timeout), m_con(con), m_timer(con.m_pservice_endpoint->get_io_service()), m_timer_started(false),
      m_cancel_timer_called(false), m_timer_cancelled(false), m_command(command)
    {
      if(m_con.start_outer_call())
      {
        MDEBUG(con.get_context_ref() << "anvoke_handler, timeout: " << timeout);
        m_timer.expires_after(std::chrono::milliseconds(timeout));
        m_timer.async_wait([&con, command, cb, timeout](const boost::system::error_code& ec)
        {
          if(ec == boost::asio::error::operation_aborted)
            return;
          MINFO(con.get_context_ref() << "Timeout on invoke operation happened, command: " << command << " timeout: " << timeout);
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
    bool m_timer_started;
    bool m_cancel_timer_called;
    bool m_timer_cancelled;
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
          MINFO(con.get_context_ref() << "Timeout on invoke operation happened, command: " << command << " timeout: " << timeout);
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
      MERROR("Adding response handler to a released object");
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
    ASSERT_OR_LOG(0 == m_wait_count, "Failed to wait for operation completion. m_wait_count = " << m_wait_count);

    MTRACE(m_connection_context << "~async_protocol_handler()");

    }
    catch (...) { /* ignore */ }
  }

  bool start_outer_call()
  {
    MTRACE(m_connection_context << "[levin_protocol] -->> start_outer_call");
    if(!m_pservice_endpoint->add_ref())
    {
      MERROR(m_connection_context << "[levin_protocol] -->> start_outer_call failed");
      return false;
    }
    m_wait_count++;
    return true;
  }
  bool finish_outer_call()
  {
    MTRACE(m_connection_context << "[levin_protocol] <<-- finish_outer_call");
    m_wait_count--;
    m_pservice_endpoint->release();
    return true;
  }

  bool release_protocol()
  {
    decltype(m_invoke_response_handlers) local_invoke_response_handlers;
    {
      LOCK_RECURSIVE_MUTEX(m_invoke_response_handlers_lock);
      local_invoke_response_handlers.swap(m_invoke_response_handlers);
      m_protocol_released = true;
    }

    // Never call callback inside critical section, that can cause deadlock. Callback can be called when
    // invoke_response_handler_base is cancelled
    std::for_each(local_invoke_response_handlers.begin(), local_invoke_response_handlers.end(), [](const std::shared_ptr<invoke_response_handler_base>& pinv_resp_hndlr) {
      pinv_resp_hndlr->cancel();
    });

    return true;
  }

  bool close()
  {
    m_close_called = true;

    m_pservice_endpoint->close();
    return true;
  }

  void update_connection_context(const connection_context& contxt)
  {
    m_connection_context = contxt;
  }

  void request_callback()
  {
    epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler(
      std::bind(&async_protocol_handler::finish_outer_call, this));

    m_pservice_endpoint->request_callback();
  }

  void handle_qued_callback()
  {
    m_config.m_pcommands_handler->callback(m_connection_context);
  }

  virtual bool handle_recv(const void* ptr, size_t cb)
  {
    if(m_close_called)
      return false; //closing connections

    if(!m_config.m_pcommands_handler)
    {
      MERROR(m_connection_context << "Commands handler not set!");
      return false;
    }

    // these should never fail, but do runtime check for safety
    const uint64_t max_packet_size = m_max_packet_size;
    ASSERT_OR_LOG_RETURN(max_packet_size >= m_cache_in_buffer.size(), false, "Bad m_cache_in_buffer.size()");
    ASSERT_OR_LOG_RETURN(max_packet_size - m_cache_in_buffer.size() >= m_fragment_buffer.size(), false, "Bad m_cache_in_buffer.size() + m_fragment_buffer.size()");

    // flipped to subtraction; prevent overflow since m_max_packet_size is variable and public
    if(cb > max_packet_size - m_cache_in_buffer.size() - m_fragment_buffer.size())
    {
      MWARNING(m_connection_context << "Maximum packet size exceed!, m_max_packet_size = " << max_packet_size
                          << ", packet received " << m_cache_in_buffer.size() +  cb
                          << ", connection will be closed.");
      return false;
    }

    m_cache_in_buffer.append((const char*)ptr, cb);

    bool is_continue = true;
    while(is_continue)
    {
      switch(m_state)
      {
      case stream_state_body:
        if(m_cache_in_buffer.size() < m_current_head.m_cb)
        {
          is_continue = false;
          if(cb >= MIN_BYTES_WANTED)
          {
            LOCK_RECURSIVE_MUTEX(m_invoke_response_handlers_lock);
            if (!m_invoke_response_handlers.empty())
            {
              //async call scenario
              std::shared_ptr<invoke_response_handler_base> response_handler = m_invoke_response_handlers.front();
              response_handler->reset_timer();
              MDEBUG(m_connection_context << "LEVIN_PACKET partial msg received. len=" << cb << ", current total " << m_cache_in_buffer.size() << "/" << m_current_head.m_cb << " (" << (100.0f * m_cache_in_buffer.size() / (m_current_head.m_cb ? m_current_head.m_cb : 1)) << "%)");
            }
          }
          break;
        }

        {
          std::string temp{};
          std::span<const uint8_t> buff_to_invoke = m_cache_in_buffer.carve((std::string::size_type)m_current_head.m_cb);
          m_state = stream_state_head;

          // abstract_tcp_server2.h manages max bandwidth for a p2p link
          if (!(m_current_head.m_flags & (LEVIN_PACKET_REQUEST | LEVIN_PACKET_RESPONSE)))
          {
            m_fragment_buffer.append(reinterpret_cast<const char*>(buff_to_invoke.data()), buff_to_invoke.size());

            if (m_fragment_buffer.size() < sizeof(bucket_head2))
            {
              MERROR(m_connection_context << "Fragmented data too small for levin header");
              return false;
            }

            temp = std::move(m_fragment_buffer);
            m_fragment_buffer.clear();
            std::memcpy(std::addressof(m_current_head), std::addressof(temp[0]), sizeof(bucket_head2));
            const size_t max_bytes = m_connection_context.get_max_bytes(m_current_head.m_command);
            if(m_current_head.m_cb > std::min<size_t>(max_packet_size, max_bytes))
            {
              MERROR(m_connection_context << "Maximum packet size exceed!, m_max_packet_size = " << std::min<size_t>(max_packet_size, max_bytes)
                << ", packet header received " << m_current_head.m_cb << ", command " << m_current_head.m_command
                << ", connection will be closed.");
              return false;
            }
            buff_to_invoke = {reinterpret_cast<const uint8_t*>(temp.data()) + sizeof(bucket_head2), temp.size() - sizeof(bucket_head2)};
          }

          bool is_response = (m_oponent_protocol_ver == LEVIN_PROTOCOL_VER_1 && m_current_head.m_flags&LEVIN_PACKET_RESPONSE);

          MDEBUG(m_connection_context << "LEVIN_PACKET_RECEIVED. [len=" << m_current_head.m_cb
            << ", flags" << m_current_head.m_flags
            << ", r?=" << m_current_head.m_have_to_return_data
            <<", cmd = " << m_current_head.m_command
            << ", v=" << m_current_head.m_protocol_version);

          if(is_response)
          {//response to some invoke

            if(!m_invoke_response_handlers.empty())
            {//async call scenario
              std::unique_lock<decltype(m_invoke_response_handlers_lock)> invoke_response_handlers_guard(m_invoke_response_handlers_lock);
              std::shared_ptr<invoke_response_handler_base> response_handler = m_invoke_response_handlers.front();
              bool timer_cancelled = response_handler->cancel_timer();
              // Don't pop handler, to avoid destroying it
              if(timer_cancelled)
                m_invoke_response_handlers.pop_front();
              invoke_response_handlers_guard.unlock();

              if(timer_cancelled)
                response_handler->handle(m_current_head.m_return_code, buff_to_invoke, m_connection_context);
            }
            else
            {
              //use sync call scenario
              if(!m_wait_count && !m_close_called)
              {
                MERROR(m_connection_context << "no active invoke when response came, wtf?");
                return false;
              }else
              {
                {
                  LOCK_RECURSIVE_MUTEX(m_local_inv_buff_lock);
                  m_local_inv_buff = std::string((const char*)buff_to_invoke.data(), buff_to_invoke.size());
                  buff_to_invoke = std::span<const uint8_t>((const uint8_t*)NULL, 0);
                  m_invoke_result_code = m_current_head.m_return_code;
                }
                m_invoke_buf_ready = true;
              }
            }
          }else
          {
            if(m_current_head.m_have_to_return_data)
            {
              std::string return_buff;
              const uint32_t return_code = m_config.m_pcommands_handler->invoke(
                m_current_head.m_command, buff_to_invoke, return_buff, m_connection_context
              );

              // peer_id remains unset if dropped
              if (m_current_head.m_command == m_connection_context.handshake_command() && m_connection_context.handshake_complete())
                m_max_packet_size = m_config.m_max_packet_size;

              bucket_head2 head = make_header(m_current_head.m_command, return_buff.size(), LEVIN_PACKET_RESPONSE, false);
              head.m_return_code = SWAP32LE(return_code);
              return_buff.insert(0, reinterpret_cast<const char*>(&head), sizeof(head));

              if(!m_pservice_endpoint->do_send(epee::string_tools::string_to_uint8_t_string(return_buff)))
                return false;

              MDEBUG(m_connection_context << "LEVIN_PACKET_SENT. [len=" << head.m_cb
                << ", flags" << head.m_flags
                << ", r?=" << head.m_have_to_return_data
                <<", cmd = " << head.m_command
                << ", ver=" << head.m_protocol_version);
            }
            else
              m_config.m_pcommands_handler->notify(m_current_head.m_command, buff_to_invoke, m_connection_context);
          }
          // reuse small buffer
          if (!temp.empty() && temp.capacity() <= 64 * 1024)
          {
            temp.clear();
            m_fragment_buffer = std::move(temp);
          }
        }
        break;
      case stream_state_head:
        {
          if(m_cache_in_buffer.size() < sizeof(bucket_head2))
          {
            if(m_cache_in_buffer.size() >= sizeof(uint64_t) && *((uint64_t*)m_cache_in_buffer.span(8).data()) != SWAP64LE(constant::LEVIN_SIGNATURE))
            {
              MWARNING(m_connection_context << "Signature mismatch, connection will be closed");
              return false;
            }
            is_continue = false;
            break;
          }

#if BYTE_ORDER == LITTLE_ENDIAN
          bucket_head2& phead = *(bucket_head2*)m_cache_in_buffer.span(sizeof(bucket_head2)).data();
#else
          bucket_head2 phead = *(bucket_head2*)m_cache_in_buffer.span(sizeof(bucket_head2)).data();
          phead.m_signature = SWAP64LE(phead.m_signature);
          phead.m_cb = SWAP64LE(phead.m_cb);
          phead.m_command = SWAP32LE(phead.m_command);
          phead.m_return_code = SWAP32LE(phead.m_return_code);
          phead.m_flags = SWAP32LE(phead.m_flags);
          phead.m_protocol_version = SWAP32LE(phead.m_protocol_version);
#endif
          if(constant::LEVIN_SIGNATURE != phead.m_signature)
          {
            LOG_ERROR_CC(m_connection_context, "Signature mismatch, connection will be closed");
            return false;
          }
          m_current_head = phead;

          m_cache_in_buffer.erase(sizeof(bucket_head2));
          m_state = stream_state_body;
          m_oponent_protocol_ver = m_current_head.m_protocol_version;
          const size_t max_bytes = m_connection_context.get_max_bytes(m_current_head.m_command);
          if(m_current_head.m_cb > std::min<size_t>(max_packet_size, max_bytes))
          {
            LOG_ERROR_CC(m_connection_context, "Maximum packet size exceed!, m_max_packet_size = " << std::min<size_t>(max_packet_size, max_bytes)
              << ", packet header received " << m_current_head.m_cb << ", command " << m_current_head.m_command
              << ", connection will be closed.");
            return false;
          }
        }
        break;
      default:
        LOG_ERROR_CC(m_connection_context, "Undefined state in levin_server_impl::connection_handler, m_state=" << m_state);
        return false;
      }
    }

    return true;
  }

  bool after_init_connection()
  {
    if (!m_connection_initialized)
    {
      m_connection_initialized = true;
      m_config.add_connection(this);
    }
    return true;
  }

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
      cb(err_code, std::span<uint8_t>(), m_connection_context);
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
        MWARNING(m_connection_context << "invoke timeout (" << m_config.m_invoke_timeout << "), closing connection ");
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

  int notify(int command, const std::span<const uint8_t> in_buff)
  {
    epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler(
                          std::bind(&async_protocol_handler::finish_outer_call, this));

    if(m_deletion_initiated)
      return LEVIN_ERROR_CONNECTION_DESTROYED;

    LOCK_RECURSIVE_MUTEX(m_call_lock);

    if(m_deletion_initiated)
      return LEVIN_ERROR_CONNECTION_DESTROYED;

    if (!send_message(command, in_buff, LEVIN_PACKET_REQUEST, false))
    {
      LOG_ERROR_CC(m_connection_context, "Failed to send notify message");
      return -1;
    }

    return 1;
  }

  //------------------------------------------------------------------------------------------
  boost::uuids::uuid get_connection_id() {return m_connection_context.m_connection_id;}
  //------------------------------------------------------------------------------------------
  t_connection_context& get_context_ref() {return m_connection_context;}
};
//------------------------------------------------------------------------------------------
template<class t_connection_context>
void async_protocol_handler_config<t_connection_context>::del_connection(async_protocol_handler<t_connection_context>* pconn)
{
  {
    LOCK_RECURSIVE_MUTEX(m_connects_lock);
    m_connects.erase(pconn->get_connection_id());
  }
  m_pcommands_handler->on_connection_close(pconn->m_connection_context);
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
void async_protocol_handler_config<t_connection_context>::delete_connections(size_t count, bool incoming)
{
  std::vector <boost::uuids::uuid> connections;
  {
    LOCK_RECURSIVE_MUTEX(m_connects_lock);
    for (auto& c: m_connects)
    {
      if (c.second->m_connection_context.m_is_income == incoming)
        connections.push_back(c.first);
    }

    // close random connections from  the provided set
    // TODO or better just keep removing random elements (performance)
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    shuffle(connections.begin(), connections.end(), std::default_random_engine(seed));
    while (count > 0 && connections.size() > 0)
    {
      try
      {
        auto i = connections.end() - 1;
        async_protocol_handler<t_connection_context> *conn = m_connects.at(*i);
        del_connection(conn);
        conn->close();
        connections.erase(i);
      }
      catch (const std::out_of_range &e)
      {
        MWARNING("Connection not found in m_connects, continuing");
      }
      --count;
    }
  }
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
void async_protocol_handler_config<t_connection_context>::del_out_connections(size_t count)
{
  delete_connections(count, false);
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
void async_protocol_handler_config<t_connection_context>::del_in_connections(size_t count)
{
  delete_connections(count, true);
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
void async_protocol_handler_config<t_connection_context>::add_connection(async_protocol_handler<t_connection_context>* pconn)
{
  {
    LOCK_RECURSIVE_MUTEX(m_connects_lock);
    m_connects[pconn->get_connection_id()] = pconn;
  }
  m_pcommands_handler->on_connection_new(pconn->m_connection_context);
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
async_protocol_handler<t_connection_context>* async_protocol_handler_config<t_connection_context>::find_connection(boost::uuids::uuid connection_id) const
{
  auto it = m_connects.find(connection_id);
  return it == m_connects.end() ? 0 : it->second;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
int async_protocol_handler_config<t_connection_context>::find_and_lock_connection(boost::uuids::uuid connection_id, async_protocol_handler<t_connection_context>*& aph)
{
  LOCK_RECURSIVE_MUTEX(m_connects_lock);
  aph = find_connection(connection_id);
  if(0 == aph)
    return LEVIN_ERROR_CONNECTION_NOT_FOUND;
  if(!aph->start_outer_call())
    return LEVIN_ERROR_CONNECTION_DESTROYED;
  return LEVIN_OK;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
int async_protocol_handler_config<t_connection_context>::invoke(int command, const std::span<const uint8_t> in_buff, std::string& buff_out, boost::uuids::uuid connection_id)
{
  async_protocol_handler<t_connection_context>* aph;
  int r = find_and_lock_connection(connection_id, aph);
  return LEVIN_OK == r ? aph->invoke(command, in_buff, buff_out) : r;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context> template<class callback_t>
int async_protocol_handler_config<t_connection_context>::invoke_async(int command, const std::span<const uint8_t> in_buff, boost::uuids::uuid connection_id, const callback_t &cb, size_t timeout)
{
  async_protocol_handler<t_connection_context>* aph;
  int r = find_and_lock_connection(connection_id, aph);
  return LEVIN_OK == r ? aph->async_invoke(command, in_buff, cb, timeout) : r;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context> template<class callback_t>
bool async_protocol_handler_config<t_connection_context>::foreach_connection(const callback_t &cb)
{
  LOCK_RECURSIVE_MUTEX(m_connects_lock);
  for(auto& c: m_connects)
  {
    async_protocol_handler<t_connection_context>* aph = c.second;
    if(!cb(aph->get_context_ref()))
      return false;
  }
  return true;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context> template<class callback_t>
bool async_protocol_handler_config<t_connection_context>::for_connection(const boost::uuids::uuid &connection_id, const callback_t &cb)
{
  LOCK_RECURSIVE_MUTEX(m_connects_lock);
  async_protocol_handler<t_connection_context>* aph = find_connection(connection_id);
  if (!aph)
    return false;
  if(!cb(aph->get_context_ref()))
    return false;
  return true;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
size_t async_protocol_handler_config<t_connection_context>::get_connections_count()
{
  LOCK_RECURSIVE_MUTEX(m_connects_lock);
  return m_connects.size();
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
size_t async_protocol_handler_config<t_connection_context>::get_out_connections_count()
{
  LOCK_RECURSIVE_MUTEX(m_connects_lock);
  size_t count = 0;
  for (const auto &c: m_connects)
    if (!c.second->m_connection_context.m_is_income)
      ++count;
  return count;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
size_t async_protocol_handler_config<t_connection_context>::get_in_connections_count()
{
  LOCK_RECURSIVE_MUTEX(m_connects_lock);
  size_t count = 0;
  for (const auto &c: m_connects)
    if (c.second->m_connection_context.m_is_income)
      ++count;
  return count;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
void async_protocol_handler_config<t_connection_context>::set_handler(levin_commands_handler<t_connection_context>* handler, void (*destroy)(levin_commands_handler<t_connection_context>*))
{
  if (m_pcommands_handler && m_pcommands_handler_destroy)
    (*m_pcommands_handler_destroy)(m_pcommands_handler);
  m_pcommands_handler = handler;
  m_pcommands_handler_destroy = destroy;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
int async_protocol_handler_config<t_connection_context>::notify(int command, const std::span<const uint8_t> in_buff, boost::uuids::uuid connection_id)
{
  async_protocol_handler<t_connection_context>* aph;
  int r = find_and_lock_connection(connection_id, aph);
  return LEVIN_OK == r ? aph->notify(command, in_buff) : r;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
bool async_protocol_handler_config<t_connection_context>::close(boost::uuids::uuid connection_id)
{
  LOCK_RECURSIVE_MUTEX(m_connects_lock);
  async_protocol_handler<t_connection_context>* aph = find_connection(connection_id);
  if (!aph)
    return false;
  if (!aph->close())
    return false;
  m_connects.erase(connection_id);
  return true;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
bool async_protocol_handler_config<t_connection_context>::update_connection_context(const t_connection_context& contxt)
{
  LOCK_RECURSIVE_MUTEX(m_connects_lock);
  async_protocol_handler<t_connection_context>* aph = find_connection(contxt.m_connection_id);
  if(0 == aph)
    return false;
  aph->update_connection_context(contxt);
  return true;
}
//------------------------------------------------------------------------------------------
template<class t_connection_context>
bool async_protocol_handler_config<t_connection_context>::request_callback(boost::uuids::uuid connection_id)
{
  async_protocol_handler<t_connection_context>* aph;
  int r = find_and_lock_connection(connection_id, aph);
  if(LEVIN_OK == r)
  {
    aph->request_callback();
    return true;
  }
  else
  {
    return false;
  }
}
}
}
