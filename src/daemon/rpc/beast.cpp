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

#include "beast.hpp"

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio.hpp>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <functional>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

namespace cryptonote {

  class http_connection : public std::enable_shared_from_this<http_connection>
  {
  public:
    http_connection(tcp::socket socket, core_rpc_server& rpc)
      : socket_(std::move(socket)), rpc_(rpc)
    {
    }

    // Initiate the asynchronous operations associated with the connection.
    void
    start()
    {
      request_parser_.body_limit
        ((std::numeric_limits<std::uint64_t>::max)());

      read_request();
      check_deadline();
    }

  private:
    // The socket for the currently connected client.
    tcp::socket socket_;
    core_rpc_server& rpc_;

    // The buffer for performing reads.
    // beast::flat_buffer buffer_{2 << 16};
    beast::flat_buffer buffer_;

    // The request message.
    http::request_parser<http::string_body> request_parser_;
    http::request<http::string_body> request_;

    // The response message.
    http::response<http::dynamic_body> response_;

    // The timer for putting a deadline on connection processing.
    boost::asio::steady_timer deadline_{
      socket_.get_executor(), std::chrono::seconds(60)};

    // Asynchronously receive a complete request message.
    void
    read_request()
    {
      auto self = shared_from_this();

      http::async_read
        (
         socket_,
         buffer_,
         request_parser_,
         [self](beast::error_code ec,
                std::size_t bytes_transferred)
         {
           boost::ignore_unused(bytes_transferred);
           if(!ec)
             self->process_request();
         });
    }

    // Determine what needs to be done with the request message.
    void
    process_request()
    {

      request_ = request_parser_.get();
      response_.version(request_.version());
      response_.keep_alive(false);

      switch(request_.method())
        {
        case http::verb::get:
        case http::verb::post:
          response_.result(http::status::ok);
          response_.set(http::field::server, "Beast");

          response_.set
            (
             http::field::content_type
             , "application/json; charset=utf-8"
             );

          rpc_response();
          break;

        default:
          // We return responses indicating an error if
          // we do not recognize the request method.
          response_.result(http::status::bad_request);
          response_.set(http::field::content_type, "text/plain");
          beast::ostream(response_.body())
            << "Invalid request-method '"
            << std::string(request_.method_string())
            << "'";
          break;
        }

      write_response();
    }

    template<class t_request, class t_response, typename T>
    void process_json(T f) {
      const std::string body_ = request_.body();
      const std::optional<std::string> maybe_res = handle_json
        <
          t_request
        , t_response
        >
        (
         body_
         , [&](const auto x, auto& y) {
           return f(x, y);
         }
         );


      if(!maybe_res) {
        response_.result(http::status::bad_request);
        return;
      }

      beast::ostream(response_.body())
        << *maybe_res
        ;
    }

    template<class t_request, class t_response, typename T>
    void process_json_rpc
    (
     epee::serialization::portable_storage ps
     , T f
     ) {
      epee::json_rpc::request<t_request> req{};

      if(!req.load(ps))
        {
          epee::json_rpc::error_response fail_resp{};
          fail_resp.jsonrpc = "2.0";
          fail_resp.id = req.id;
          fail_resp.error.code = -32602;
          fail_resp.error.message = "Invalid params";

          std::string res_str;
          epee::serialization::store_t_to_json(fail_resp, res_str);
          beast::ostream(response_.body()) << res_str;

          return;
        }

      epee::json_rpc::response
        <
          t_response
        , epee::json_rpc::dummy_error
        > resp;

      resp.jsonrpc = "2.0";
      resp.id = req.id;

      epee::json_rpc::error_response fail_resp{};
      fail_resp.jsonrpc = "2.0";
      fail_resp.id = req.id;

      // LOG_VERBOSE("Calling RPC method " + callback_name);
      bool res = false;

      try {
        res = f(req.params, resp.result, fail_resp.error);
      }
      catch (const std::exception &e) {
        LOG_ERROR
          (
           "Failed to "
           + std::string("on_sync_info")
           + "(): "
           + std::string(e.what())
           );
      }

      if (!res)
        {
          std::string res_str;
          epee::serialization::store_t_to_json(fail_resp, res_str);
          beast::ostream(response_.body()) << res_str;

          return;
        }

      std::string res_str;
      epee::serialization::store_t_to_json(resp, res_str);
      beast::ostream(response_.body()) << res_str;
    }

    void rpc_response()
    {
      const std::string body_ = request_.body();

      if(request_.target() == "/echo")
        {
          beast::ostream(response_.body())
            << body_
            << "\n"
            ;
        }

#define JSON(uri, callback, request_t)                          \
      else if(request_.target() == uri)                         \
        {                                                       \
          process_json<request_t::request, request_t::response> \
            (                                                   \
             std::bind                                          \
             (                                                  \
              &core_rpc_server::callback                        \
              , &rpc_                                           \
              , std::placeholders::_1                           \
              , std::placeholders::_2));                        \
        }                                                       \


      JSON("/get_blocks"
           , on_get_blocks
           , COMMAND_RPC_GET_BLOCKS_FAST)

      JSON("/get_hashes"
           , on_get_hashes
           , COMMAND_RPC_GET_HASHES_FAST)

      JSON("/is_output_key_image_spent"
           , on_is_output_key_image_spent
           , COMMAND_RPC_IS_KEY_IMAGE_SPENT)

      JSON("/send_raw_transaction"
           , on_send_raw_tx
           , COMMAND_RPC_SEND_RAW_TX)

      JSON("/start_mining"
           , on_start_mining
           , COMMAND_RPC_START_MINING)

      JSON("/stop_mining"
           , on_stop_mining
           , COMMAND_RPC_STOP_MINING)

      JSON("/mining_status"
           , on_mining_status
           , COMMAND_RPC_MINING_STATUS)

      JSON("/get_peer_list"
           , on_get_peer_list
           , COMMAND_RPC_GET_PEER_LIST)

      JSON("/get_transaction_pool"
           , on_get_transaction_pool
           , COMMAND_RPC_GET_TRANSACTION_POOL)

      JSON("/get_transaction_pool_hashes"
           , on_get_transaction_pool_hashes
           , COMMAND_RPC_GET_TRANSACTION_POOL_HASHES)

      JSON("/get_info"
           , on_get_info
           , COMMAND_RPC_GET_INFO)

      JSON("/get_tx_outputs"
           , on_get_tx_outputs
           , COMMAND_RPC_GET_OUTPUTS)

      JSON("/pop_blocks"
           , on_pop_blocks
           , COMMAND_RPC_POP_BLOCKS)

      JSON("/get_transactions"
           , on_get_transactions
           , COMMAND_RPC_GET_TRANSACTIONS)


      else if(request_.target() == "/json_rpc")
        {
          epee::serialization::portable_storage ps;
          if(!ps.load_from_json(body_)) {
            epee::json_rpc::error_response rsp{};
            rsp.jsonrpc = "2.0";
            rsp.error.code = -32700;
            rsp.error.message = "Parse error";

            std::string res_str;
            epee::serialization::store_t_to_json(rsp, res_str);
            beast::ostream(response_.body()) << res_str;

            return;
          }

          epee::serialization::storage_entry id_;
          id_ = epee::serialization::storage_entry(std::string());
          ps.get_value("id", id_, nullptr);

          std::string callback_name;
          if(!ps.get_value("method", callback_name, nullptr))
            {
              epee::json_rpc::error_response rsp;
              rsp.jsonrpc = "2.0";
              rsp.error.code = -32600;
              rsp.error.message = "Invalid Request";

              std::string res_str;
              epee::serialization::store_t_to_json(rsp, res_str);
              beast::ostream(response_.body()) << res_str;

              return;
            }

#define JSON_RPC(method, callback, request_t)                         \
          else if(callback_name == method) {                          \
            process_json_rpc<request_t::request, request_t::response> \
              (                                                       \
               ps                                                     \
               , std::bind                                            \
               (                                                      \
                &core_rpc_server::callback                            \
                , &rpc_                                               \
                , std::placeholders::_1                               \
                , std::placeholders::_2                               \
                , std::placeholders::_3));                            \
          } 

          JSON_RPC("sync_info"
                   , on_sync_info
                   , COMMAND_RPC_SYNC_INFO)

          JSON_RPC("get_block_header_by_hash"
                   , on_get_block_header_by_hash
                   , COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH)

          JSON_RPC("get_block_header_by_height"
                   , on_get_block_header_by_height
                   , COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT)

          JSON_RPC("get_block"
                   , on_get_block
                   , COMMAND_RPC_GET_BLOCK)

          JSON_RPC("get_connections"
                   ,on_get_connections
                   , COMMAND_RPC_GET_CONNECTIONS)

          JSON_RPC("get_info"
                   , on_get_info_json
                   , COMMAND_RPC_GET_INFO)

          JSON_RPC("set_bans"
                   , on_set_bans
                   , COMMAND_RPC_SETBANS)

          JSON_RPC("get_bans"
                   , on_get_bans
                   , COMMAND_RPC_GETBANS)

          JSON_RPC("banned"
                   , on_banned
                   , COMMAND_RPC_BANNED)

          JSON_RPC("flush_txpool"
                   , on_flush_txpool
                   , COMMAND_RPC_FLUSH_TRANSACTION_POOL)

          JSON_RPC("get_version"
                   , on_get_version
                   , COMMAND_RPC_GET_VERSION)

          JSON_RPC("get_coinbase_tx_sum"
                   , on_get_coinbase_tx_sum
                   , COMMAND_RPC_GET_COINBASE_TX_SUM)

          JSON_RPC("relay_tx"
                   , on_relay_tx
                   , COMMAND_RPC_RELAY_TX)

          JSON_RPC("get_output_distribution"
                   , on_get_output_distribution
                   , COMMAND_RPC_GET_OUTPUT_DISTRIBUTION)

          JSON_RPC("flush_cache"
                   , on_flush_cache
                   , COMMAND_RPC_FLUSH_CACHE)

        }
      else
        {
          response_.result(http::status::not_found);
        }
    }


    // Asynchronously transmit the response message.
    void
    write_response()
    {
      auto self = shared_from_this();

      response_.content_length(response_.body().size());

      http::async_write
        (
         socket_,
         response_,
         [self](beast::error_code ec, std::size_t)
         {
           self->socket_.shutdown(tcp::socket::shutdown_send, ec);
           self->deadline_.cancel();
         });
    }

    // Check whether we have spent enough time on this connection.
    void
    check_deadline()
    {
      auto self = shared_from_this();

      deadline_.async_wait
        (
         [self](beast::error_code ec)
         {
           if(!ec)
             {
               // Close socket to cancel any outstanding operation.
               self->socket_.close(ec);
             }
         });
    }
  };

  // "Loop" forever accepting new connections.
  void
  http_server
  (
   tcp::acceptor& acceptor
   , tcp::socket& socket
   , core_rpc_server& rpc
   )
  {
    acceptor.async_accept
      (
       socket,
       [&](beast::error_code ec)
       {
         if(!ec)
           std::make_shared<http_connection>
             (
              std::move(socket)
              , rpc
              )
             ->start()
             ;
         http_server(acceptor, socket, rpc);
       });
  }

  void start_beast
  (
   const std::string_view ip
   , const std::string_view rpc_port
   , boost::asio::io_context& ioc
   , core_rpc_server& rpc
   ) {
    const auto address = boost::asio::ip::make_address(ip);
    unsigned short port =
      static_cast<unsigned short>(std::atoi(rpc_port.data()));

    tcp::acceptor acceptor{ioc, {address, port}};
    tcp::socket socket{ioc};
    http_server(acceptor, socket, rpc);

    ioc.run();
  }

} // cryptonote
