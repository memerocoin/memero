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


#include "tools/epee/include/net/net_utils_base.h"
#include "tools/epee/include/net/net_ssl.h"

#include <boost/asio.hpp>





#ifndef MAKE_IP
#define MAKE_IP( a1, a2, a3, a4 )	(a1|(a2<<8)|(a3<<16)|(a4<<24))
#endif


namespace epee
{
namespace net_utils
{
	struct direct_connect
	{
		std::future<boost::asio::ip::tcp::socket>
			operator()(const std::string& addr, const std::string& port, boost::asio::steady_timer&) const;
	};


  enum try_connect_result_t
		{
			CONNECT_SUCCESS,
			CONNECT_FAILURE,
			CONNECT_NO_SSL,
		};

  class blocked_mode_client
	{

    struct handler_obj
    {
      handler_obj(boost::system::error_code& error,	size_t& bytes_transferred):ref_error(error), ref_bytes_transferred(bytes_transferred)
      {}
      handler_obj(const handler_obj& other_obj):ref_error(other_obj.ref_error), ref_bytes_transferred(other_obj.ref_bytes_transferred)
      {}

      boost::system::error_code& ref_error;
      size_t& ref_bytes_transferred;

      void operator()(const boost::system::error_code& error, // Result of operation.
                      std::size_t bytes_transferred           // Number of bytes read.
                      )
      {
        ref_error = error;
        ref_bytes_transferred = bytes_transferred;
      }
    };

	public:
			blocked_mode_client() :
				m_io_service(),
				m_ctx(boost::asio::ssl::context::tlsv12),
				m_socket(boost::asio::ip::tcp::socket(m_io_service)),
				m_connector(direct_connect{}),
				m_ssl_options(epee::net_utils::ssl_support_t::e_ssl_support_disabled),
				m_initialized(true),
				m_connected(false),
				m_deadline(m_io_service, std::chrono::steady_clock::time_point::max()),
				m_shutdowned(false),
				m_bytes_sent(0),
				m_bytes_received(0)
		{
			check_deadline();
		}

		/*! The first/second parameters are host/port respectively. The third
		    parameter is for setting the timeout callback - the timer is
		    already set by the caller, the callee only needs to set the
		    behavior.

		    Additional asynchronous operations should be queued using the
		    `io_service` from the timer. The implementation should assume
		    multi-threaded I/O processing.

		    If the callee cannot start an asynchronous operation, an exception
		    should be thrown to signal an immediate failure.

		    The return value is a future to a connected socket. Asynchronous
		    failures should use the `set_exception` method. */
		using connect_func = std::future<boost::asio::ip::tcp::socket>(const std::string&, const std::string&, boost::asio::steady_timer&);

    ~blocked_mode_client()
		{
			//profile_tools::local_coast lc("~blocked_mode_client()", 3);
			try { shutdown(); }
			catch(...) { /* ignore */ }
		}

		void set_ssl(ssl_options_t ssl_options);
    bool connect(const std::string& addr, int port, std::chrono::milliseconds timeout);
    try_connect_result_t try_connect(const std::string& addr, const std::string& port, std::chrono::milliseconds timeout);
    bool connect(const std::string& addr, const std::string& port, std::chrono::milliseconds timeout);
		//! Change the connection routine (proxy, etc.)
		void set_connector(std::function<connect_func> connector);
		bool disconnect();
		bool send(const std::string& buff, std::chrono::milliseconds timeout);
    bool send(const void* data, size_t sz);
		bool is_connected(bool *ssl = NULL);
		bool recv(std::string& buff, std::chrono::milliseconds timeout);
		bool recv_n(std::string& buff, int64_t sz, std::chrono::milliseconds timeout);
		bool shutdown();
		boost::asio::io_service& get_io_service();
		boost::asio::ip::tcp::socket& socket();
		uint64_t get_bytes_sent() const;
		uint64_t get_bytes_received() const;

	private:

		void check_deadline();

	protected:
		bool write(const void* data, size_t sz, boost::system::error_code& ec);
		void async_write(const void* data, size_t sz, boost::system::error_code& ec);
		void async_read(char* buff, size_t sz, boost::asio::detail::transfer_at_least_t transfer_at_least, handler_obj& hndlr);

	protected:
		boost::asio::io_service m_io_service;
		boost::asio::ssl::context m_ctx;
		boost::asio::ip::tcp::socket m_socket;
		std::function<connect_func> m_connector;
		ssl_options_t m_ssl_options;
		bool m_initialized;
		bool m_connected;
		boost::asio::steady_timer m_deadline;
    std::atomic<bool> m_shutdowned;
		std::atomic<uint64_t> m_bytes_sent;
		std::atomic<uint64_t> m_bytes_received;
	};


	/************************************************************************/
	/*                                                                      */
	/************************************************************************/
	class async_blocked_mode_client: public blocked_mode_client
	{
	public:
		async_blocked_mode_client() :
      m_send_deadline(m_io_service)
		{

			// Start the persistent actor that checks for deadline expiry.
			check_send_deadline();
		}
		~async_blocked_mode_client()
		{
			m_send_deadline.cancel();
		}

		bool shutdown()
		{
			blocked_mode_client::shutdown();
			m_send_deadline.cancel();
			return true;
		}

		inline
			bool send(const void* data, size_t sz)
		{
			try
			{
				/*
				m_send_deadline.expires_after(std::chrono::milliseconds(m_reciev_timeout));

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
				while(ec == boost::asio::error::would_block)
				{
					m_io_service.run_one();
				}*/

				boost::system::error_code ec;

				size_t writen = write(data, sz, ec);

				if (!writen || ec)
				{
					LOG_PRINT_L3("Problems at write: " << ec.message());
					return false;
				}else
				{
					m_send_deadline.expires_at(std::chrono::steady_clock::time_point::max());
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


	private:

		boost::asio::steady_timer m_send_deadline;


		void check_send_deadline()
		{
			// Check whether the deadline has passed. We compare the deadline against
			// the current time since a new asynchronous operation may have moved the
			// deadline before this actor had a chance to run.
			if (m_send_deadline.expires_at() <= std::chrono::steady_clock::now())
			{
				// The deadline has passed. The socket is closed so that any outstanding
				// asynchronous operations are cancelled. This allows the blocked
				// connect(), read_line() or write_line() functions to return.
				LOG_PRINT_L3("Timed out socket");
			  socket().close();

				// There is no longer an active deadline. The expiry is set to positive
				// infinity so that the actor takes no action until a new deadline is set.
				m_send_deadline.expires_at(std::chrono::steady_clock::time_point::max());
			}

			// Put the actor back to sleep.
			m_send_deadline.async_wait(std::bind(&async_blocked_mode_client::check_send_deadline, this));
		}
	};
}
}

