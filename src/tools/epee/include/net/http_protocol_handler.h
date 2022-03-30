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


#include "net_utils_base.h"
#include "http_base.h"




namespace epee
{
namespace net_utils
{
	namespace http
	{
		struct multipart_entry
		{
			std::list<std::pair<std::string, std::string> > m_etc_header_fields;
			std::string m_content_disposition;
			std::string m_content_type;
			std::string m_body;
		};

		bool match_boundary(const std::string& content_type, std::string& boundary);
	  bool parse_header(std::string::const_iterator it_begin, std::string::const_iterator it_end, multipart_entry& entry);
		bool handle_part_of_multipart(std::string::const_iterator it_begin, std::string::const_iterator it_end, multipart_entry& entry);
    bool analize_http_method(const std::smatch& result, http::http_method& method, int& http_ver_major, int& http_ver_minor);


		/************************************************************************/
		/*                                                                      */
		/************************************************************************/
		struct http_server_config
		{
			std::vector<std::string> m_access_control_origins;
			std::recursive_mutex m_lock;
		};

		/************************************************************************/
		/*                                                                      */
		/************************************************************************/
		template<class t_connection_context  = epee::net_utils::connection_context_base>
		class simple_http_connection_handler
		{
		public:
			typedef t_connection_context connection_context;//t_connection_context epee::net_utils::connection_context_base connection_context;
			typedef http_server_config config_type;

			simple_http_connection_handler(i_service_endpoint* psnd_hndlr, config_type& config, t_connection_context& conn_context);
			virtual ~simple_http_connection_handler(){}

			bool release_protocol()
			{
				return true;
			}

			virtual bool thread_init()
			{
				return true;
			}

			virtual bool thread_deinit()
			{
				return true;
			}
			bool after_init_connection()
			{
				return true;
			}
			virtual bool handle_recv(const void* ptr, size_t cb);
			virtual bool handle_request(const http::http_request_info& query_info, http_response_info& response);

		private:
			enum machine_state{
				http_state_retriving_comand_line,
				http_state_retriving_header,
				http_state_retriving_body,
				http_state_connection_close,
				http_state_error
			};

			enum body_transfer_type{
				http_body_transfer_chunked,
				http_body_transfer_measure,//mean "Content-Length" valid
				http_body_transfer_chunked_instead_measure,
				http_body_transfer_connection_close,
				http_body_transfer_multipart,
				http_body_transfer_undefined
			};

			bool handle_buff_in(std::string& buf);

			bool analize_cached_request_header_and_invoke_state(size_t pos);

			bool handle_invoke_query_line();
			bool parse_cached_header(http_header_info& body_info, const std::string& m_cache_to_process, size_t pos);
			std::string::size_type match_end_of_header(const std::string& buf);
			bool get_len_from_content_lenght(const std::string& str, size_t& len);
			bool handle_retriving_query_body();
			bool handle_query_measure();
			bool set_ready_state();
			bool slash_to_back_slash(std::string& str);
			std::string get_response_header(const http_response_info& response);

			//major function
			inline bool handle_request_and_send_response(const http::http_request_info& query_info);


			std::string m_root_path;
			std::string m_cache;
			machine_state m_state;
			body_transfer_type m_body_transfer_type;
		
	bool m_is_stop_handling;
			http::http_request_info m_query_info;
			size_t m_len_summary, m_len_remain;
			config_type& m_config;
			bool m_want_close;
			size_t m_newlines;
		protected:
			i_service_endpoint* m_psnd_hndlr;
			t_connection_context& m_conn_context;
		};

		using t_connection_context = epee::net_utils::connection_context_base;
		struct i_http_server_handler
		{
			virtual ~i_http_server_handler(){}
			virtual bool handle_http_request(const http_request_info& query_info,
																						 http_response_info& response,
																						 t_connection_context& m_conn_context) = 0;
			virtual bool init_server_thread(){return true;}
			virtual bool deinit_server_thread(){return true;}
		};

		struct custum_handler_config: public http_server_config
		{
			i_http_server_handler* m_phandler;
		};

		/************************************************************************/
		/*                                                                      */
		/************************************************************************/

		class http_custom_handler: public simple_http_connection_handler<t_connection_context>
		{
		public:
			typedef custum_handler_config config_type;

			http_custom_handler(i_service_endpoint* psnd_hndlr, config_type& config, t_connection_context& conn_context)
				: simple_http_connection_handler<t_connection_context>(psnd_hndlr, config, conn_context),
					m_config(config)
			{}
			inline bool handle_request(const http_request_info& query_info, http_response_info& response)
			{
				LOG_ERROR_AND_RETURN_UNLESS(m_config.m_phandler, false, "m_config.m_phandler is NULL!!!!");

				//fill with default values
				response.m_mime_tipe = "text/plain";
				response.m_response_code = 200;
				response.m_response_comment = "OK";
				response.m_body.clear();

				return m_config.m_phandler->handle_http_request(query_info, response, this->m_conn_context);
			}

			virtual bool thread_init()
			{
				return m_config.m_phandler->init_server_thread();
			}

			virtual bool thread_deinit()
			{
				return m_config.m_phandler->deinit_server_thread();
			}
			void handle_qued_callback()
			{}
			bool after_init_connection()
			{
				return true;
			}

		private:
			//simple_http_connection_handler::config_type m_stub_config;
			config_type& m_config;
		};
	}
}
}

#include "http_protocol_handler.inl"
