#include "tools/epee/include/net/net_helper.h"

#include <boost/lambda/lambda.hpp>

namespace epee
{
namespace net_utils
{
	std::future<boost::asio::ip::tcp::socket>
	direct_connect::operator()(const std::string& addr, const std::string& port, boost::asio::steady_timer& timeout) const
	{
		// Get a list of endpoints corresponding to the server name.
		//////////////////////////////////////////////////////////////////////////
		boost::asio::ip::tcp::resolver resolver(GET_IO_SERVICE(timeout));
		boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), addr, port, boost::asio::ip::tcp::resolver::query::canonical_name);

		bool try_ipv6 = false;
		boost::asio::ip::tcp::resolver::iterator iterator;
		boost::asio::ip::tcp::resolver::iterator end;
		boost::system::error_code resolve_error;
		try
		{
			iterator = resolver.resolve(query, resolve_error);
			if(iterator == end) // Documentation states that successful call is guaranteed to be non-empty
			{
				// if IPv4 resolution fails, try IPv6.  Unintentional outgoing IPv6 connections should only
				// be possible if for some reason a hostname was given and that hostname fails IPv4 resolution,
				// so at least for now there should not be a need for a flag "using ipv6 is ok"
				try_ipv6 = true;
			}

		}
		catch (const boost::system::system_error& e)
		{
			if (resolve_error != boost::asio::error::host_not_found &&
					resolve_error != boost::asio::error::host_not_found_try_again)
			{
				throw;
			}
			try_ipv6 = true;
		}
		if (try_ipv6)
		{
			boost::asio::ip::tcp::resolver::query query6(boost::asio::ip::tcp::v6(), addr, port, boost::asio::ip::tcp::resolver::query::canonical_name);
			iterator = resolver.resolve(query6);
			if (iterator == end)
				throw boost::system::system_error{boost::asio::error::fault, "Failed to resolve " + addr};
		}

		//////////////////////////////////////////////////////////////////////////

		struct new_connection
		{
			std::promise<boost::asio::ip::tcp::socket> result_;
			boost::asio::ip::tcp::socket socket_;

			explicit new_connection(boost::asio::io_service& io_service)
			  : result_(), socket_(io_service)
			{}
		};

		const auto shared = std::make_shared<new_connection>(GET_IO_SERVICE(timeout));
		timeout.async_wait([shared] (boost::system::error_code error)
		{
			if (error != boost::system::errc::operation_canceled && shared && shared->socket_.is_open())
			{
				shared->socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
				shared->socket_.close();
			}
		});
		shared->socket_.async_connect(*iterator, [shared] (boost::system::error_code error)
		{
			if (shared)
			{
				if (error) {
					shared->result_.set_exception(std::make_exception_ptr(std::system_error{error}));
        }
				else
					shared->result_.set_value(std::move(shared->socket_));
			}
		});
		return shared->result_.get_future();
	}


  void blocked_mode_client::set_ssl(ssl_options_t ssl_options)
  {
    if (ssl_options)
      m_ctx = ssl_options.create_context();
    else
      m_ctx = boost::asio::ssl::context(boost::asio::ssl::context::tlsv12);
    m_ssl_options = std::move(ssl_options);
  }

  bool blocked_mode_client::connect(const std::string& addr, int port, std::chrono::milliseconds timeout)
  {
    return connect(addr, std::to_string(port), timeout);
  }

  try_connect_result_t blocked_mode_client::try_connect(const std::string& addr, const std::string& port, std::chrono::milliseconds timeout)
  {
      m_deadline.expires_after(timeout);
      std::future<boost::asio::ip::tcp::socket> connection = m_connector(addr, port, m_deadline);
      for (;;)
      {
        m_io_service.reset();
        m_io_service.run_one();

        if (connection.wait_for(std::chrono::seconds(0)) == std::future_status::ready)
          break;
      }

      m_ssl_socket->next_layer() = connection.get();
      m_deadline.cancel();
      if (m_ssl_socket->next_layer().is_open())
      {
        m_connected = true;
        m_deadline.expires_at(std::chrono::steady_clock::time_point::max());
        // SSL Options
        if (m_ssl_options.support == epee::net_utils::ssl_support_t::e_ssl_support_enabled || m_ssl_options.support == epee::net_utils::ssl_support_t::e_ssl_support_autodetect)
        {
          if (!m_ssl_options.handshake(*m_ssl_socket, boost::asio::ssl::stream_base::client, {}, addr, timeout))
          {
            if (m_ssl_options.support == epee::net_utils::ssl_support_t::e_ssl_support_autodetect)
            {
              boost::system::error_code ignored_ec;
              m_ssl_socket->next_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored_ec);
              m_ssl_socket->next_layer().close();
              m_connected = false;
              return CONNECT_NO_SSL;
            }
            else
            {
              MWARNING("Failed to establish SSL connection");
              m_connected = false;
              return CONNECT_FAILURE;
            }
          }
        }
        return CONNECT_SUCCESS;
      }else
      {
        MWARNING("Some problems at connect, expected open socket");
        return CONNECT_FAILURE;
      }

  }

  bool blocked_mode_client::connect(const std::string& addr, const std::string& port, std::chrono::milliseconds timeout)
  {
    m_connected = false;
    try
    {
      m_ssl_socket->next_layer().close();

      // Set SSL options
      // disable sslv2
      m_ssl_socket = std::make_shared<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(m_io_service, m_ctx);

      // Get a list of endpoints corresponding to the server name.

      try_connect_result_t try_connect_result = try_connect(addr, port, timeout);
      if (try_connect_result == CONNECT_FAILURE)
        return false;
      if (m_ssl_options.support == epee::net_utils::ssl_support_t::e_ssl_support_autodetect)
      {
        if (try_connect_result == CONNECT_NO_SSL)
        {
          MERROR("SSL handshake failed on an autodetect connection, reconnecting without SSL");
          m_ssl_options.support = epee::net_utils::ssl_support_t::e_ssl_support_disabled;
          if (try_connect(addr, port, timeout) != CONNECT_SUCCESS)
            return false;
        }
      }
    }
    catch(const boost::system::system_error& er)
    {
      MDEBUG("Some problems at connect, message: " << er.what());
      return false;
    }
    catch(...)
    {
      MDEBUG("Some fatal problems.");
      return false;
    }

    return true;
  }
  //! Change the connection routine (proxy, etc.)
  void blocked_mode_client::set_connector(std::function<connect_func> connector)
  {
    m_connector = std::move(connector);
  }

  bool blocked_mode_client::disconnect()
  {
    try
    {
      if(m_connected)
      {
        m_connected = false;
        if(m_ssl_options)
          shutdown_ssl();
        m_ssl_socket->next_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
      }
    }
    catch(const boost::system::system_error& /*er*/)
    {
      //LOG_ERROR("Some problems at disconnect, message: " << er.what());
      return false;
    }
    catch(...)
    {
      //LOG_ERROR("Some fatal problems.");
      return false;
    }
    return true;
  }


  bool blocked_mode_client::send(const std::string& buff, std::chrono::milliseconds timeout)
  {

    try
    {
      m_deadline.expires_after(timeout);

      // Set up the variable that receives the result of the asynchronous
      // operation. The error code is set to would_block to signal that the
      // operation is incomplete. Asio guarantees that its asynchronous
      // operations will never fail with would_block, so any other value in
      // ec indicates completion.
      boost::system::error_code ec = boost::asio::error::would_block;

      // Start the asynchronous operation itself. The boost::lambda function
      // object is used as a callback and will update the ec variable when the
      // operation completes. The blocking_udp_client.cpp example shows how you
      // can use std::bind rather than boost::lambda.
      async_write(buff.c_str(), buff.size(), ec);

      // Block until the asynchronous operation has completed.
      while (ec == boost::asio::error::would_block)
      {
        m_io_service.reset();
        m_io_service.run_one();
      }

      if (ec)
      {
        LOG_PRINT_L3("Problems at write: " << ec.message());
        m_connected = false;
        return false;
      }else
      {
        m_deadline.expires_at(std::chrono::steady_clock::time_point::max());
        m_bytes_sent += buff.size();
      }
    }

    catch(const boost::system::system_error& er)
    {
      LOG_ERROR("Some problems at connect, message: " << er.what());
      return false;
    }
    catch(...)
    {
      LOG_ERROR("Some fatal problems.");
      return false;
    }

    return true;
  }

  bool blocked_mode_client::send(const void* data, size_t sz)
  {
    try
    {
      /*
      m_deadline.expires_after(std::chrono::milliseconds(m_reciev_timeout));

      // Set up the variable that receives the result of the asynchronous
      // operation. The error code is set to would_block to signal that the
      // operation is incomplete. Asio guarantees that its asynchronous
      // operations will never fail with would_block, so any other value in
      // ec indicates completion.
      boost::system::error_code ec = boost::asio::error::would_block;

      // Start the asynchronous operation itself. The boost::lambda function
      // object is used as a callback and will update the ec variable when the
      // operation completes. The blocking_udp_client.cpp example shows how you
      // can use std::bind rather than boost::lambda.
      boost::asio::async_write(m_socket, boost::asio::buffer(data, sz), boost::lambda::var(ec) = boost::lambda::_1);

      // Block until the asynchronous operation has completed.
      while (ec == boost::asio::error::would_block)
      {
        m_io_service.run_one();
      }
      */
      boost::system::error_code ec;

      size_t writen = write(data, sz, ec);

      if (!writen || ec)
      {
        LOG_PRINT_L3("Problems at write: " << ec.message());
        m_connected = false;
        return false;
      }else
      {
        m_deadline.expires_at(std::chrono::steady_clock::time_point::max());
        m_bytes_sent += sz;
      }
    }

    catch(const boost::system::system_error& er)
    {
      LOG_ERROR("Some problems at send, message: " << er.what());
      m_connected = false;
      return false;
    }
    catch(...)
    {
      LOG_ERROR("Some fatal problems.");
      return false;
    }

    return true;
  }

  bool blocked_mode_client::is_connected(bool *ssl)
  {
    if (!m_connected || !m_ssl_socket->next_layer().is_open())
      return false;
    if (ssl)
      *ssl = m_ssl_options.support != ssl_support_t::e_ssl_support_disabled;
    return true;
  }

  bool blocked_mode_client::recv(std::string& buff, std::chrono::milliseconds timeout)
  {

    try
    {
      // Set a deadline for the asynchronous operation. Since this function uses
      // a composed operation (async_read_until), the deadline applies to the
      // entire operation, rather than individual reads from the socket.
      m_deadline.expires_after(timeout);

      // Set up the variable that receives the result of the asynchronous
      // operation. The error code is set to would_block to signal that the
      // operation is incomplete. Asio guarantees that its asynchronous
      // operations will never fail with would_block, so any other value in
      // ec indicates completion.
      //boost::system::error_code ec = boost::asio::error::would_block;

      // Start the asynchronous operation itself. The boost::lambda function
      // object is used as a callback and will update the ec variable when the
      // operation completes. The blocking_udp_client.cpp example shows how you
      // can use std::bind rather than boost::lambda.

      boost::system::error_code ec = boost::asio::error::would_block;
      size_t bytes_transfered = 0;

      handler_obj hndlr(ec, bytes_transfered);

      static const size_t max_size = 16384;
      buff.resize(max_size);

      async_read(&buff[0], max_size, boost::asio::transfer_at_least(1), hndlr);

      // Block until the asynchronous operation has completed.
      while (ec == boost::asio::error::would_block && !m_shutdowned)
      {
        m_io_service.reset();
        m_io_service.run_one();
      }


      if (ec)
      {
                  MTRACE("READ ENDS: Connection err_code " << ec.value());
                  if(ec == boost::asio::error::eof)
                  {
                    MTRACE("Connection err_code eof.");
                    //connection closed there, empty
                    buff.clear();
                    return true;
                  }

        MDEBUG("Problems at read: " << ec.message());
                  m_connected = false;
        return false;
      }else
      {
                  MTRACE("READ ENDS: Success. bytes_tr: " << bytes_transfered);
        m_deadline.expires_at(std::chrono::steady_clock::time_point::max());
      }

      /*if(!bytes_transfered)
        return false;*/

      m_bytes_received += bytes_transfered;
      buff.resize(bytes_transfered);
      return true;
    }

    catch(const boost::system::system_error& er)
    {
      LOG_ERROR("Some problems at read, message: " << er.what());
      m_connected = false;
      return false;
    }
    catch(...)
    {
      LOG_ERROR("Some fatal problems at read.");
      return false;
    }



    return false;

  }

  bool blocked_mode_client::recv_n(std::string& buff, int64_t sz, std::chrono::milliseconds timeout)
  {

    try
    {
      // Set a deadline for the asynchronous operation. Since this function uses
      // a composed operation (async_read_until), the deadline applies to the
      // entire operation, rather than individual reads from the socket.
      m_deadline.expires_after(timeout);

      // Set up the variable that receives the result of the asynchronous
      // operation. The error code is set to would_block to signal that the
      // operation is incomplete. Asio guarantees that its asynchronous
      // operations will never fail with would_block, so any other value in
      // ec indicates completion.
      //boost::system::error_code ec = boost::asio::error::would_block;

      // Start the asynchronous operation itself. The boost::lambda function
      // object is used as a callback and will update the ec variable when the
      // operation completes. The blocking_udp_client.cpp example shows how you
      // can use std::bind rather than boost::lambda.

      buff.resize(static_cast<size_t>(sz));
      boost::system::error_code ec = boost::asio::error::would_block;
      size_t bytes_transfered = 0;


      handler_obj hndlr(ec, bytes_transfered);
      async_read((char*)buff.data(), buff.size(), boost::asio::transfer_at_least(buff.size()), hndlr);

      // Block until the asynchronous operation has completed.
      while (ec == boost::asio::error::would_block && !m_shutdowned)
      {
        m_io_service.run_one();
      }

      if (ec)
      {
        LOG_PRINT_L3("Problems at read: " << ec.message());
        m_connected = false;
        return false;
      }else
      {
        m_deadline.expires_at(std::chrono::steady_clock::time_point::max());
      }

      m_bytes_received += bytes_transfered;
      if(bytes_transfered != buff.size())
      {
        LOG_ERROR("Transferred mismatch with transfer_at_least value: m_bytes_transferred=" << bytes_transfered << " at_least value=" << buff.size());
        return false;
      }

      return true;
    }

    catch(const boost::system::system_error& er)
    {
      LOG_ERROR("Some problems at read, message: " << er.what());
      m_connected = false;
      return false;
    }
    catch(...)
    {
      LOG_ERROR("Some fatal problems at read.");
      return false;
    }



    return false;
  }

  bool blocked_mode_client::shutdown()
  {
    m_deadline.cancel();
    boost::system::error_code ec;
    if(m_ssl_options)
      shutdown_ssl();
    m_ssl_socket->next_layer().cancel(ec);
    if(ec)
      MDEBUG("Problems at cancel: " << ec.message());
    m_ssl_socket->next_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    if(ec)
      MDEBUG("Problems at shutdown: " << ec.message());
    m_ssl_socket->next_layer().close(ec);
    if(ec)
      MDEBUG("Problems at close: " << ec.message());
    m_shutdowned = true;
    m_connected = false;
    return true;
  }

  boost::asio::io_service& blocked_mode_client::get_io_service()
  {
    return m_io_service;
  }

  boost::asio::ip::tcp::socket& blocked_mode_client::get_socket()
  {
    return m_ssl_socket->next_layer();
  }

  uint64_t blocked_mode_client::get_bytes_sent() const
  {
    return m_bytes_sent;
  }

  uint64_t blocked_mode_client::get_bytes_received() const
  {
    return m_bytes_received;
  }

  void blocked_mode_client::check_deadline()
  {
    // Check whether the deadline has passed. We compare the deadline against
    // the current time since a new asynchronous operation may have moved the
    // deadline before this actor had a chance to run.
    if (m_deadline.expires_at() <= std::chrono::steady_clock::now())
    {
      // The deadline has passed. The socket is closed so that any outstanding
      // asynchronous operations are cancelled. This allows the blocked
      // connect(), read_line() or write_line() functions to return.
      LOG_PRINT_L3("Timed out socket");
      m_connected = false;
      m_ssl_socket->next_layer().close();

      // There is no longer an active deadline. The expiry is set to positive
      // infinity so that the actor takes no action until a new deadline is set.
      m_deadline.expires_at(std::chrono::steady_clock::time_point::max());
    }

    // Put the actor back to sleep.
    m_deadline.async_wait(std::bind(&blocked_mode_client::check_deadline, this));
  }

  void blocked_mode_client::shutdown_ssl() {
    // ssl socket shutdown blocks if server doesn't respond. We close after 2 secs
    boost::system::error_code ec = boost::asio::error::would_block;
    m_deadline.expires_after(std::chrono::milliseconds(2000));
    m_ssl_socket->async_shutdown(boost::lambda::var(ec) = boost::lambda::_1);
    while (ec == boost::asio::error::would_block)
    {
      m_io_service.reset();
      m_io_service.run_one();
    }
    // Ignore "short read" error
    if (ec.category() == boost::asio::error::get_ssl_category() &&
        ec.value() !=
#if BOOST_VERSION >= 106200
        boost::asio::ssl::error::stream_truncated
#else // older Boost supports only OpenSSL 1.0, so 1.0-only macros are appropriate
        ERR_PACK(ERR_LIB_SSL, 0, SSL_R_SHORT_READ)
#endif
        )
      MDEBUG("Problems at ssl shutdown: " << ec.message());
  }

  bool blocked_mode_client::write(const void* data, size_t sz, boost::system::error_code& ec)
  {
    bool success;
    if(m_ssl_options.support != ssl_support_t::e_ssl_support_disabled)
      success = boost::asio::write(*m_ssl_socket, boost::asio::buffer(data, sz), ec);
    else
      success = boost::asio::write(m_ssl_socket->next_layer(), boost::asio::buffer(data, sz), ec);
    return success;
  }

  void blocked_mode_client::async_write(const void* data, size_t sz, boost::system::error_code& ec)
  {
    if(m_ssl_options.support != ssl_support_t::e_ssl_support_disabled)
      boost::asio::async_write(*m_ssl_socket, boost::asio::buffer(data, sz), boost::lambda::var(ec) = boost::lambda::_1);
    else
      boost::asio::async_write(m_ssl_socket->next_layer(), boost::asio::buffer(data, sz), boost::lambda::var(ec) = boost::lambda::_1);
  }

  void blocked_mode_client::async_read(char* buff, size_t sz, boost::asio::detail::transfer_at_least_t transfer_at_least, handler_obj& hndlr)
  {
    if(m_ssl_options.support == ssl_support_t::e_ssl_support_disabled)
      boost::asio::async_read(m_ssl_socket->next_layer(), boost::asio::buffer(buff, sz), transfer_at_least, hndlr);
    else
      boost::asio::async_read(*m_ssl_socket, boost::asio::buffer(buff, sz), transfer_at_least, hndlr);

  }
}
}

