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

#include "tools/epee/include/net/levin_protocol_handler_async.h"

#include "tools/epee/functional/span.hpp"

#include <random>

namespace epee
{
namespace levin
{

  //------------------------------------------------------------------------------------------
  void async_protocol_handler_config::del_connection(async_protocol_handler* pconn)
  {
    {
      LOCK_RECURSIVE_MUTEX(m_connects_lock);
      m_connects.erase(pconn->get_connection_id());
    }
    m_pcommands_handler->on_connection_close(pconn->m_connection_context);
  }
  //------------------------------------------------------------------------------------------
  void async_protocol_handler_config::delete_connections(size_t count, bool incoming)
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
              async_protocol_handler *conn = m_connects.at(*i);
              del_connection(conn);
              conn->close();
              connections.erase(i);
            }
          catch (const std::out_of_range &e)
            {
              LOG_WARNING("Connection not found in m_connects, continuing");
            }
          --count;
        }
    }
  }
  //------------------------------------------------------------------------------------------
  void async_protocol_handler_config::del_out_connections(size_t count)
  {
    delete_connections(count, false);
  }
  //------------------------------------------------------------------------------------------
  void async_protocol_handler_config::del_in_connections(size_t count)
  {
    delete_connections(count, true);
  }
  //------------------------------------------------------------------------------------------
  void async_protocol_handler_config::add_connection(async_protocol_handler* pconn)
  {
    {
      LOCK_RECURSIVE_MUTEX(m_connects_lock);
      m_connects[pconn->get_connection_id()] = pconn;
    }
    m_pcommands_handler->on_connection_new(pconn->m_connection_context);
  }
  //------------------------------------------------------------------------------------------
  async_protocol_handler* async_protocol_handler_config::find_connection(boost::uuids::uuid connection_id) const
  {
    auto it = m_connects.find(connection_id);
    return it == m_connects.end() ? 0 : it->second;
  }
  //------------------------------------------------------------------------------------------
  int async_protocol_handler_config::find_and_lock_connection(boost::uuids::uuid connection_id, async_protocol_handler*& aph)
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

  size_t async_protocol_handler_config::get_connections_count()
  {
    LOCK_RECURSIVE_MUTEX(m_connects_lock);
    return m_connects.size();
  }
  //------------------------------------------------------------------------------------------

  size_t async_protocol_handler_config::get_out_connections_count()
  {
    LOCK_RECURSIVE_MUTEX(m_connects_lock);
    size_t count = 0;
    for (const auto &c: m_connects)
      if (!c.second->m_connection_context.m_is_income)
        ++count;
    return count;
  }
  //------------------------------------------------------------------------------------------

  size_t async_protocol_handler_config::get_in_connections_count()
  {
    LOCK_RECURSIVE_MUTEX(m_connects_lock);
    size_t count = 0;
    for (const auto &c: m_connects)
      if (c.second->m_connection_context.m_is_income)
        ++count;
    return count;
  }
  //------------------------------------------------------------------------------------------

  void async_protocol_handler_config::set_handler(levin_commands_handler<t_connection_context>* handler, void (*destroy)(levin_commands_handler<t_connection_context>*))
  {
    if (m_pcommands_handler && m_pcommands_handler_destroy)
      (*m_pcommands_handler_destroy)(m_pcommands_handler);
    m_pcommands_handler = handler;
    m_pcommands_handler_destroy = destroy;
  }
  //------------------------------------------------------------------------------------------

  int async_protocol_handler_config::notify(int command, const std::span<const uint8_t> in_buff, boost::uuids::uuid connection_id)
  {
    async_protocol_handler* aph;
    int r = find_and_lock_connection(connection_id, aph);
    return LEVIN_OK == r ? aph->notify(command, in_buff) : r;
  }
  //------------------------------------------------------------------------------------------

  bool async_protocol_handler_config::close(boost::uuids::uuid connection_id)
  {
    LOCK_RECURSIVE_MUTEX(m_connects_lock);
    async_protocol_handler* aph = find_connection(connection_id);
    if (!aph)
      return false;
    if (!aph->close())
      return false;
    m_connects.erase(connection_id);
    return true;
  }
  //------------------------------------------------------------------------------------------

  bool async_protocol_handler_config::update_connection_context(const t_connection_context& contxt)
  {
    LOCK_RECURSIVE_MUTEX(m_connects_lock);
    async_protocol_handler* aph = find_connection(contxt.m_connection_id);
    if(0 == aph)
      return false;
    aph->update_connection_context(contxt);
    return true;
  }
  //------------------------------------------------------------------------------------------

  bool async_protocol_handler_config::request_callback(boost::uuids::uuid connection_id)
  {
    async_protocol_handler* aph;
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


  bool async_protocol_handler::send_message(uint32_t command, std::span<const uint8_t> in_buff, uint32_t flags, bool expect_response)
  {
    const bucket_head2 head = make_header(command, in_buff.size(), flags, expect_response);
    std::span<const uint8_t> head_span = pod_to_span(head);
    const auto head_string = epee::blob::data(head_span.data(), head_span.size());
    const auto in_buff_string = epee::blob::data(in_buff.data(), in_buff.size());
    if(!m_pservice_endpoint->do_send(head_string + in_buff_string))
      return false;

    LOG_DEBUG_MUTE(m_connection_context << "LEVIN_PACKET_SENT. [len=" << head.m_cb
                   << ", flags" << head.m_flags
                   << ", r?=" << head.m_have_to_return_data
                   <<", cmd = " << head.m_command
                   << ", ver=" << head.m_protocol_version);
    return true;
  }

  bool async_protocol_handler::start_outer_call()
  {
    LOG_TRACE
      (
       m_connection_context.to_str()
       + "[levin_protocol] -->> start_outer_call"
       );
    if(!m_pservice_endpoint->add_ref())
      {
        LOG_ERROR(m_connection_context.to_str() + "[levin_protocol] -->> start_outer_call failed");
        return false;
      }
    m_wait_count++;
    return true;
  }


  bool async_protocol_handler::finish_outer_call()
  {
    LOG_TRACE
      (
       m_connection_context.to_str()
       + "[levin_protocol] <<-- finish_outer_call"
       );
    m_wait_count--;
    m_pservice_endpoint->release();
    return true;
  }

  bool async_protocol_handler::release_protocol()
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

  bool async_protocol_handler::close()
  {
    m_close_called = true;

    m_pservice_endpoint->close();
    return true;
  }



  void async_protocol_handler::update_connection_context(const connection_context& contxt)
  {
    m_connection_context = contxt;
  }

  void async_protocol_handler::request_callback()
  {
    epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler(
                                                                                                                std::bind(&async_protocol_handler::finish_outer_call, this));

    m_pservice_endpoint->request_callback();
  }

  void async_protocol_handler::handle_qued_callback()
  {
    m_config.m_pcommands_handler->callback(m_connection_context);
  }

  bool async_protocol_handler::handle_recv(const void* ptr, size_t cb)
  {
    if(m_close_called)
      return false; //closing connections

    if(!m_config.m_pcommands_handler)
      {
        LOG_ERROR(m_connection_context.to_str() + "Commands handler not set!");
        return false;
      }

    // these should never fail, but do runtime check for safety
    const uint64_t max_packet_size = m_max_packet_size;
    LOG_ERROR_AND_RETURN_UNLESS(max_packet_size >= m_cache_in_buffer.size(), false, "Bad m_cache_in_buffer.size()");
    LOG_ERROR_AND_RETURN_UNLESS(max_packet_size - m_cache_in_buffer.size() >= m_fragment_buffer.size(), false, "Bad m_cache_in_buffer.size() + m_fragment_buffer.size()");

    // flipped to subtraction; prevent overflow since m_max_packet_size is variable and public
    if(cb > max_packet_size - m_cache_in_buffer.size() - m_fragment_buffer.size())
      {
        LOG_WARNING
          (
           m_connection_context.to_str()
           + "Maximum packet size exceed!, m_max_packet_size = "
           + std::to_string(max_packet_size)
           + ", packet received "
           + std::to_string(m_cache_in_buffer.size() + cb)
           + ", connection will be closed."
           );
        return false;
      }

    m_cache_in_buffer.append(epee::blob::span((const uint8_t*)ptr, cb));

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
                        LOG_DEBUG_MUTE(m_connection_context << "LEVIN_PACKET partial msg received. len=" << cb << ", current total " << m_cache_in_buffer.size() << "/" << m_current_head.m_cb << " (" << (100.0f * m_cache_in_buffer.size() / (m_current_head.m_cb ? m_current_head.m_cb : 1)) << "%)");
                      }
                  }
                break;
              }

            {
              epee::blob::data temp;
              epee::blob::data buff_to_invoke =
                m_cache_in_buffer.carve
                ((std::string::size_type)m_current_head.m_cb);

              m_state = stream_state_head;

              // abstract_tcp_server2.h manages max bandwidth for a p2p link
              if (!(m_current_head.m_flags & (LEVIN_PACKET_REQUEST | LEVIN_PACKET_RESPONSE)))
                {
                  m_fragment_buffer.append(buff_to_invoke);
                  if (m_fragment_buffer.size() < sizeof(bucket_head2))
                    {
                      LOG_ERROR
                        (
                         m_connection_context.to_str()
                         + "Fragmented data too small for levin header"
                         );
                      return false;
                    }

                  temp = m_fragment_buffer;
                  m_fragment_buffer.clear();

                  m_current_head = epee::span_to_pod<bucket_head2>(temp);
                  const size_t max_bytes = m_connection_context.get_max_bytes(m_current_head.m_command);
                  if(m_current_head.m_cb > std::min<size_t>(max_packet_size, max_bytes))
                    {
                      LOG_ERROR
                        (
                         m_connection_context.to_str()
                         + "Maximum packet size exceed!, m_max_packet_size = "
                         + std::to_string(std::min<size_t>(max_packet_size, max_bytes))
                         + ", packet header received "
                         + std::to_string(m_current_head.m_cb)
                         + ", command "
                         + std::to_string(m_current_head.m_command)
                         + ", connection will be closed."
                         );
                      return false;
                    }
                  buff_to_invoke = {reinterpret_cast<const uint8_t*>(temp.data()) + sizeof(bucket_head2), temp.size() - sizeof(bucket_head2)};
                }

              bool is_response = (m_oponent_protocol_ver == LEVIN_PROTOCOL_VER_1 && m_current_head.m_flags&LEVIN_PACKET_RESPONSE);

              LOG_DEBUG_MUTE(m_connection_context << "LEVIN_PACKET_RECEIVED. [len=" << m_current_head.m_cb
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
                          LOG_ERROR(m_connection_context.to_str() + "no active invoke when response came");
                          return false;
                        }else
                        {
                          {
                            LOCK_RECURSIVE_MUTEX(m_local_inv_buff_lock);
                            m_local_inv_buff = buff_to_invoke;
                            buff_to_invoke.clear();
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

                      if(!m_pservice_endpoint->do_send(epee::string_tools::string_to_blob(return_buff)))
                        return false;

                      LOG_DEBUG_MUTE(m_connection_context << "LEVIN_PACKET_SENT. [len=" << head.m_cb
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
                  m_fragment_buffer.clear();
                }
            }
            break;
          case stream_state_head:
            {
              if(m_cache_in_buffer.size() < sizeof(bucket_head2))
                {
                  if(m_cache_in_buffer.size() >= sizeof(uint64_t) && *((uint64_t*)m_cache_in_buffer.span().subspan(8).data()) != SWAP64LE(constant::LEVIN_SIGNATURE))
                    {
                      LOG_WARNING
                        (
                         m_connection_context.to_str()
                         + "Signature mismatch, connection will be closed"
                         );
                      return false;
                    }
                  is_continue = false;
                  break;
                }

              const bucket_head2 phead =
                epee::span_to_pod<bucket_head2>(m_cache_in_buffer.span());

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
                  LOG_ERROR_CC
                    (
                     m_connection_context
                     , "Maximum packet size exceed!, m_max_packet_size = "
                     + std::to_string(std::min<size_t>(max_packet_size, max_bytes))
                     + ", packet header received "
                     + std::to_string(m_current_head.m_cb)
                     + ", command "
                     + std::to_string(m_current_head.m_command)
                     + ", connection will be closed."
                     );
                  return false;
                }
            }
            break;
          default:
            LOG_ERROR_CC
              (
               m_connection_context
               , "Undefined state in levin_server_impl::connection_handler, m_state="
               + std::to_string(m_state)
               );
            return false;
          }
      }

    return true;
  }

  bool async_protocol_handler::after_init_connection()
  {
    if (!m_connection_initialized)
      {
        m_connection_initialized = true;
        m_config.add_connection(this);
      }
    return true;
  }

  int async_protocol_handler::notify(int command, const std::span<const uint8_t> in_buff)
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




} // levin
} // epee
