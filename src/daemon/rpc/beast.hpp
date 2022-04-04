/*

Copyright 2021 fuwa

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/


#include "network/rpc/core_rpc_server.h"
#include "cryptonote/protocol/cryptonote_protocol_handler.h"

#include <boost/asio.hpp>

namespace cryptonote {

  void start_beast
  (
   const std::string_view ip
   , const std::string_view rpc_port
   , boost::asio::io_context& ioc
   , core_rpc_server& rpc
   );

  template<class t_request, class t_response, typename T>
  std::optional<std::string> handle_json
  (
   std::string x
   , T f
   ) {
    t_request req;
    epee::serialization::load_t_from_json(req, x);

    t_response res;
    const bool r = f(req, res);

    if (!r) {
      return {};
    }

    std::string res_str;
    if(!epee::serialization::store_t_to_json(res, res_str)) {
      return {};
    }

    return res_str;
  }


}
