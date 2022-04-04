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

#include "levin_base.h"

#include "tools/epee/include/storages/portable_storage_template_helper.h"

#include "config/lol.hpp"


namespace
{
  constexpr epee::serialization::portable_storage::limits_t
  default_levin_limits = {
    8192, // objects
    16384, // fields
    16384, // strings
  };
}

namespace epee
{
namespace net_utils
{

  using context_t = epee::net_utils::connection_context_base;
  void on_levin_traffic(const context_t &context, bool initiator, bool sent, bool error, size_t bytes, const char *category);
  void on_levin_traffic(const context_t &context, bool initiator, bool sent, bool error, size_t bytes, int command);


  template<class t_result, class t_arg, class callback_t, class t_transport>
  bool async_invoke_remote_command2(const epee::net_utils::connection_context_base &context, int command, const t_arg& out_struct, t_transport& transport, const callback_t &cb, size_t inv_timeout = constant::LEVIN_DEFAULT_TIMEOUT_PRECONFIGURED)
  {
    const boost::uuids::uuid &conn_id = context.m_connection_id;
    typename serialization::portable_storage stg;
    const_cast<t_arg&>(out_struct).store(stg);//TODO: add true const support to searilzation
    std::string buff_to_send;
    stg.store_to_binary(buff_to_send);
    on_levin_traffic(context, true, true, false, buff_to_send.size(), command);
    int res = transport.invoke_async(command, epee::string_tools::string_to_blob(buff_to_send), conn_id, [cb, command](int code, const std::span<const uint8_t> buff, typename t_transport::connection_context& context)->bool
    {
      t_result result_struct{};
      if( code <=0 )
        {
          if (!buff.empty())
            on_levin_traffic(context, true, false, true, buff.size(), command);
          LOG_PRINT_L1
            (
             "Failed to invoke command "
             + std::to_string(command)
             + " return code "
             + std::to_string(code)
             );
          cb(code, result_struct, context);
          return false;
        }
      serialization::portable_storage stg_ret;
      if(!stg_ret.load_from_binary(buff, &default_levin_limits))
        {
          on_levin_traffic(context, true, false, true, buff.size(), command);
          LOG_ERROR("Failed to load_from_binary on command " + std::to_string(command));
          cb(epee::levin::LEVIN_ERROR_FORMAT, result_struct, context);
          return false;
        }
      if (!result_struct.load(stg_ret))
        {
          on_levin_traffic(context, true, false, true, buff.size(), command);
          LOG_ERROR("Failed to load result struct on command " + std::to_string(command));
          cb(epee::levin::LEVIN_ERROR_FORMAT, result_struct, context);
          return false;
        }
      on_levin_traffic(context, true, false, false, buff.size(), command);
      cb(code, result_struct, context);
      return true;
    }, inv_timeout);
    if( res <=0 )
      {
        LOG_PRINT_L1
          (
           "Failed to invoke command "
           + std::to_string(command)
           + " return code "
           + std::to_string(res)
           );
        return false;
      }
    return true;
  }

  //----------------------------------------------------------------------------------------------------
  template<class t_owner, class t_in_type, class t_out_type, class t_context, class callback_t>
  int buff_to_t_adapter
  (
   int command
   , const std::span<const uint8_t> in_buff
   , epee::blob::data& buff_out, callback_t cb, t_context& context
   )
  {
    serialization::portable_storage strg;
    if(!strg.load_from_binary(in_buff, &default_levin_limits))
      {
        on_levin_traffic(context, false, false, true, in_buff.size(), command);
        LOG_ERROR("Failed to load_from_binary in command " + std::to_string(command));
        return -1;
      }
    boost::value_initialized<t_in_type> in_struct;
    boost::value_initialized<t_out_type> out_struct;

    if (!static_cast<t_in_type&>(in_struct).load(strg))
      {
        on_levin_traffic(context, false, false, true, in_buff.size(), command);
        LOG_ERROR("Failed to load in_struct in command " + std::to_string(command));
        return -1;
      }
    on_levin_traffic(context, false, false, false, in_buff.size(), command);
    int res = cb(command, static_cast<t_in_type&>(in_struct), static_cast<t_out_type&>(out_struct), context);
    serialization::portable_storage strg_out;
    static_cast<t_out_type&>(out_struct).store(strg_out);

    std::string buff_out_str;
    if(!strg_out.store_to_binary(buff_out_str))
      {
        LOG_ERROR("Failed to store_to_binary in command" + std::to_string(command));
        return -1;
      }

    buff_out = epee::string_tools::string_to_blob(buff_out_str);
    on_levin_traffic(context, false, true, false, buff_out.size(), command);

    return res;
  }

  template<class t_owner, class t_in_type, class t_context, class callback_t>
  int buff_to_t_adapter(t_owner* powner, int command, const std::span<const uint8_t> in_buff, callback_t cb, t_context& context)
  {
    serialization::portable_storage strg;
    if(!strg.load_from_binary(in_buff, &default_levin_limits))
      {
        on_levin_traffic(context, false, false, true, in_buff.size(), command);
        LOG_ERROR("Failed to load_from_binary in notify " + std::to_string(command));
        return -1;
      }
    boost::value_initialized<t_in_type> in_struct;
    if (!static_cast<t_in_type&>(in_struct).load(strg))
      {
        on_levin_traffic(context, false, false, true, in_buff.size(), command);
        LOG_ERROR("Failed to load in_struct in notify " + std::to_string(command));
        return -1;
      }
    on_levin_traffic(context, false, false, false, in_buff.size(), command);
    return cb(command, in_struct, context);
  }


} //net_utils
} // epee

