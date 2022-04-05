// Copyright (c) 2014-2020, The Monero Project
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
//
#include "rpc_args.h"

#include "tools/epee/functional/hex.hpp"
#include "tools/epee/include/string_tools.h"

#include "tools/common/command_line.h"

#include <boost/algorithm/string.hpp>
#include <boost/system/error_code.hpp>

namespace cryptonote
{
namespace rpc_server {
  std::optional<std::pair<uint32_t, uint16_t>>
  parse_args(const boost::program_options::variables_map & vm)
  {
    const auto rpc_ip_str = command_line::get_arg
      (
       vm 
       , cryptonote::rpc_server::arg_rpc_bind_ip
       );

    const auto rpc_port_str = command_line::get_arg
      (
       vm 
       , cryptonote::rpc_server::arg_rpc_bind_port
       );

    uint32_t rpc_ip;
    uint16_t rpc_port;

    using namespace epee::string_tools;
    if (!get_ip_int32_from_string(rpc_ip, rpc_ip_str))
      {
        std::cerr << "Invalid IP: " << rpc_ip_str << std::endl;
        return {};
      }
    if (!get_xtype_from_string(rpc_port, rpc_port_str))
      {
        std::cerr << "Invalid port: " << rpc_port_str << std::endl;
        return {};
      }

    return {{rpc_ip, rpc_port}};
  }

} // rpc_server
} // cryptonote
