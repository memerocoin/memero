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

namespace epee
{
namespace net_utils
{

#define CHAIN_LEVIN_INVOKE_MAP2(context_type)                           \
  int invoke(int command, const std::span<const uint8_t> in_buff, epee::blob::data& buff_out, context_type& context) \
  {                                                                     \
    bool handled = false;                                               \
    return handle_invoke_map(false, command, in_buff, buff_out, context, handled); \
  }

#define CHAIN_LEVIN_NOTIFY_MAP2(context_type)                           \
  int notify(int command, const std::span<const uint8_t> in_buff, context_type& context) \
  {                                                                     \
    bool handled = false;                                               \
    epee::blob::data fake_str;                                          \
    return handle_invoke_map(true, command, in_buff, fake_str, context, handled); \
  }


#define CHAIN_LEVIN_INVOKE_MAP()                                        \
  int invoke                                                            \
  (                                                                     \
   int command                                                          \
   , const std::span<const uint8_t> in_buff                             \
   , epee::blob::data & buff_out                                        \
   , epee::net_utils::connection_context_base& context                  \
                                                                      ) \
  {                                                                     \
    bool handled = false;                                               \
    return handle_invoke_map(false, command, in_buff, buff_out, context, handled); \
  }

#define CHAIN_LEVIN_NOTIFY_MAP()                                        \
  int notify(int command, const std::span<const uint8_t> in_buff, epee::net_utils::connection_context_base& context) \
  {                                                                     \
    bool handled = false; std::string fake_str;                         \
    return handle_invoke_map(true, command, in_buff, fake_str, context, handled); \
  }

#define CHAIN_LEVIN_NOTIFY_STUB()                                       \
  int notify(int command, const std::span<const uint8_t> in_buff, epee::net_utils::connection_context_base& context) \
  {                                                                     \
    return -1;                                                          \
  }

#define BEGIN_INVOKE_MAP2(owner_type)                                   \
  template <class t_context> int handle_invoke_map(bool is_notify, int command, const std::span<const uint8_t> in_buff, epee::blob::data& buff_out, t_context& context, bool& handled) \
  {                                                                     \
  try {                                                                 \
  typedef owner_type internal_owner_type_name;

#define HANDLE_INVOKE2(command_id, func, type_name_in, typename_out)    \
  if(!is_notify && command_id == command)                               \
    {handled=true;return epee::net_utils::buff_to_t_adapter<internal_owner_type_name, type_name_in, typename_out>(this, command, in_buff, buff_out, std::bind(func, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4), context);}

#define HANDLE_INVOKE_T2(COMMAND, func)                                 \
  if(!is_notify && COMMAND::ID == command)                              \
    {handled=true;return epee::net_utils::buff_to_t_adapter<internal_owner_type_name, typename COMMAND::request, typename COMMAND::response>(command, in_buff, buff_out, std::bind(func, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4), context);}


#define HANDLE_NOTIFY2(command_id, func, type_name_in)                  \
  if(is_notify && command_id == command)                                \
    {handled=true;return epee::net_utils::buff_to_t_adapter<internal_owner_type_name, type_name_in>(this, command, in_buff, std::bind(func, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), context);}

#define HANDLE_NOTIFY_T2(NOTIFY, func)                                  \
  if(is_notify && NOTIFY::ID == command)                                \
    {handled=true;return epee::net_utils::buff_to_t_adapter<internal_owner_type_name, typename NOTIFY::request>(this, command, in_buff, std::bind(func, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), context);}


#define CHAIN_INVOKE_MAP2(func)                                         \
  {                                                                     \
    int res = func(is_notify, command, in_buff, buff_out, context, handled); \
    if(handled)                                                         \
      return res;                                                       \
  }

#define CHAIN_INVOKE_MAP_TO_OBJ2(obj)                                   \
  {                                                                     \
    int res = obj.handle_invoke_map(is_notify, command, in_buff, buff_out, context, handled); \
    if(handled)                                                         \
      return res;                                                       \
  }

#define CHAIN_INVOKE_MAP_TO_OBJ_FORCE_CONTEXT(obj, context_type)        \
  {                                                                     \
    int res = obj.handle_invoke_map(is_notify, command, in_buff, buff_out, static_cast<context_type>(context), handled); \
    if(handled) return res;                                             \
  }


#define END_INVOKE_MAP2()                                               \
  LOG_ERROR("Unknown command:" + std::to_string(command));              \
  on_levin_traffic(context, false, false, true, in_buff.size(), "invalid-command"); \
  return epee::levin::LEVIN_ERROR_CONNECTION_HANDLER_NOT_DEFINED;       \
}                                                                       \
  catch (const std::exception &e) {                                     \
    LOG_ERROR("Error in handle_invoke_map: " + std::string(e.what()));  \
    return epee::levin::LEVIN_ERROR_CONNECTION_TIMEDOUT; /* seems kinda appropriate */ \
  }                                                                     \
}

} //net_utils
} // epee
