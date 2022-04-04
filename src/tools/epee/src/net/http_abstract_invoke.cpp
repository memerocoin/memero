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

#include "tools/epee/include/net/http_abstract_invoke.h"

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>


namespace epee
{
  namespace net_utils
  {
    std::optional<std::string> beast_http
    (
     const std::string host
     , const std::string port
     , const std::string uri
     , const std::string request_body
     , const std::optional<std::string> content_type
     )
    {
      const int version = 11;

      namespace beast = boost::beast;     // from <boost/beast.hpp>
      namespace http = beast::http;       // from <boost/beast/http.hpp>
      namespace net = boost::asio;        // from <boost/asio.hpp>
      using tcp = net::ip::tcp;           // from <boost/asio/ip/tcp.hpp>

      net::io_context ioc;

      // These objects perform our I/O
      tcp::resolver resolver(ioc);
      beast::tcp_stream stream(ioc);

      // // Look up the domain name
      auto const results = resolver.resolve(host, port);

      // Make the connection on the IP address we get from a lookup
      stream.connect(results);

      // // Set up an HTTP GET request message
      http::request<http::string_body> req{http::verb::post, uri, version};
      req.body() = request_body;

      req.set(http::field::host, host);
      req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
      req.set(http::field::content_length, std::to_string(request_body.size()));
      if (content_type) {
        req.set(http::field::content_type, *content_type);
      }

      LOG_DEBUG("Beast REQ:");
      // LOG_DEBUG(req);


      // Send the HTTP request to the remote host
      http::write(stream, req);

      // This buffer is used for reading and must be persisted
      beast::flat_buffer buffer;

      // Declare a container to hold the response
      http::response<http::string_body> res;

      // Receive the HTTP response
      http::read(stream, buffer, res);

      // Write the message to standard out
      LOG_DEBUG("Beast RESPONSE");
      // LOG_DEBUG(res);

      // Gracefully close the socket
      beast::error_code ec;
      stream.socket().shutdown(tcp::socket::shutdown_both, ec);

      // not_connected happens sometimes
      // so don't
      //
      if(ec && ec != beast::errc::not_connected) {
        LOG_ERROR
          (
           "Failed to invoke http request to  " + uri + ", not connected"
           );
        return {};
      }

      return res.body();
    }

    std::optional<std::string> beast_http_json
    (
     const std::string host
     , const std::string port
     , const std::string uri
     , const std::string request_body
     )
    {
      return beast_http
        (
         host
         , port
         , uri
         , request_body
         , "application/json; charset=utf-8"
         );
    }
  }
}
