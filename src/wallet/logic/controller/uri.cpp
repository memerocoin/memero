// Copyright (c) 2021, The Lolnero Project
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
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers


#include "uri.hpp"

#include <boost/algorithm/string.hpp>

#include "net/abstract_http_client.h"
#include "cryptonote/core/cryptonote_tx_utils.h"

namespace wallet {
namespace logic {
namespace controller {
namespace uri {

  //----------------------------------------------------------------------------------------------------
  std::string make_uri
  (
   const std::string &address
   , const uint64_t amount
   , const std::string &tx_description
   , const std::string &recipient_name
   , const cryptonote::network_type nettype
   , std::string &error
   )
  {
    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, nettype, address))
      {
        error = std::string("wrong address: ") + address;
        return std::string();
      }

    std::string uri = "lolnero:" + address;
    unsigned int n_fields = 0;

    if (amount > 0)
      {
        // URI encoded amount is in decimal units, not atomic units
        uri += (n_fields++ ? "&" : "?") + std::string("tx_amount=") + cryptonote::print_money(amount);
      }

    if (!recipient_name.empty())
      {
        uri += (n_fields++ ? "&" : "?") + std::string("recipient_name=") + epee::net_utils::conver_to_url_format(recipient_name);
      }

    if (!tx_description.empty())
      {
        uri += (n_fields++ ? "&" : "?") + std::string("tx_description=") + epee::net_utils::conver_to_url_format(tx_description);
      }

    return uri;
  }

  //----------------------------------------------------------------------------------------------------
  bool parse_uri
  (
   const std::string &uri
   , const cryptonote::network_type nettype
   , std::string &address
   , uint64_t &amount
   , std::string &tx_description
   , std::string &recipient_name
   , std::vector<std::string> &unknown_parameters
   , std::string &error
   )
  {
    if (uri.substr(0, 8) != "lolnero:")
      {
        error = std::string("URI has wrong scheme (expected \"lolnero:\"): ") + uri;
        return false;
      }

    std::string remainder = uri.substr(8);
    const char *ptr = strchr(remainder.c_str(), '?');
    address = ptr ? remainder.substr(0, ptr-remainder.c_str()) : remainder;

    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, nettype, address))
      {
        error = std::string("URI has wrong address: ") + address;
        return false;
      }
    if (!strchr(remainder.c_str(), '?'))
      return true;

    std::vector<std::string> arguments;
    std::string body = remainder.substr(address.size() + 1);
    if (body.empty())
      return true;
    boost::split(arguments, body, boost::is_any_of("&"));
    std::set<std::string> have_arg;
    for (const auto &arg: arguments)
      {
        std::vector<std::string> kv;
        boost::split(kv, arg, boost::is_any_of("="));
        if (kv.size() != 2)
          {
            error = std::string("URI has wrong parameter: ") + arg;
            return false;
          }
        if (have_arg.find(kv[0]) != have_arg.end())
          {
            error = std::string("URI has more than one instance of " + kv[0]);
            return false;
          }
        have_arg.insert(kv[0]);

        if (kv[0] == "tx_amount")
          {
            amount = 0;
            if (!cryptonote::parse_amount(amount, kv[1]))
              {
                error = std::string("URI has invalid amount: ") + kv[1];
                return false;
              }
          }
        else if (kv[0] == "recipient_name")
          {
            recipient_name = epee::net_utils::convert_from_url_format(kv[1]);
          }
        else if (kv[0] == "tx_description")
          {
            tx_description = epee::net_utils::convert_from_url_format(kv[1]);
          }
        else
          {
            unknown_parameters.push_back(arg);
          }
      }
    return true;
  }

} // uri
} // controller
} // logic
} // wallet
