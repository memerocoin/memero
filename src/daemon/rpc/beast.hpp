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

}
