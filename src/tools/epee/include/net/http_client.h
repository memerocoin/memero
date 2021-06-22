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

#include <ctype.h>
#include <regex>
#include <string_view>
#include <algorithm>
#include <cctype>
#include <functional>

#include <boost/lexical_cast.hpp>

#include "abstract_http_client.h"
#include "http_base.h"
#include "http_client_base.h"
#include "net_helper.h"
#include "tools/epee/include/net/net_parse_helpers.h"
#include "tools/epee/include/reg_exp_definer.h"
#include "tools/epee/include/string_tools.h"
#include "tools/epee/include/syncobj.h"

//#include "shlwapi.h"

//#pragma comment(lib, "shlwapi.lib")

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net.http"

extern std::recursive_mutex gregexp_lock;


namespace epee
{
namespace net_utils
{

	/*struct url
	{
	public:
		void parse(const std::string& url_s)
		{
			const string prot_end("://");
			string::const_iterator prot_i = search(url_s.begin(), url_s.end(),
				prot_end.begin(), prot_end.end());
			protocol_.reserve(distance(url_s.begin(), prot_i));
			transform(url_s.begin(), prot_i,
				back_inserter(protocol_),
				ptr_fun<int,int>(tolower)); // protocol is icase
			if( prot_i == url_s.end() )
				return;
			advance(prot_i, prot_end.length());
			string::const_iterator path_i = find(prot_i, url_s.end(), '/');
			host_.reserve(distance(prot_i, path_i));
			transform(prot_i, path_i,
				back_inserter(host_),
				ptr_fun<int,int>(tolower)); // host is icase
			string::const_iterator query_i = find(path_i, url_s.end(), '?');
			path_.assign(path_i, query_i);
			if( query_i != url_s.end() )
				++query_i;
			query_.assign(query_i, url_s.end());
		}

		std::string protocol_;
		std::string host_;
		std::string path_;
		std::string query_;
	};*/




	//---------------------------------------------------------------------------
	namespace http
	{

    class http_simple_client_template : public i_target_handler, public abstract_http_client
		{
		private:
			enum reciev_machine_state
			{
				reciev_machine_state_header,
				reciev_machine_state_body_content_len,
				reciev_machine_state_body_connection_close,
				reciev_machine_state_body_chunked,
				reciev_machine_state_done,
				reciev_machine_state_error
			};



			enum chunked_state{
				http_chunked_state_chunk_head,
				http_chunked_state_chunk_body,
				http_chunked_state_done,
				http_chunked_state_undefined
			};


			blocked_mode_client m_net_client;
			std::string m_host_buff;
			std::string m_port;
			std::string m_header_cache;
			http_response_info m_response_info;
			size_t m_len_in_summary;
			size_t m_len_in_remain;
			//std::string* m_ptarget_buffer;
			std::shared_ptr<i_sub_handler> m_pcontent_encoding_handler;
			reciev_machine_state m_state;
			chunked_state m_chunked_state;
			std::string m_chunked_cache;
			bool m_auto_connect;
			std::recursive_mutex m_lock;

		public:
			explicit http_simple_client_template()
				: i_target_handler(), abstract_http_client()
				, m_net_client()
				, m_host_buff()
				, m_port()
				, m_header_cache()
				, m_response_info()
				, m_len_in_summary(0)
				, m_len_in_remain(0)
				, m_pcontent_encoding_handler(nullptr)
				, m_state()
				, m_chunked_state()
				, m_chunked_cache()
				, m_auto_connect(true)
				, m_lock()
			{}

			const std::string &get_host() const { return m_host_buff; };
			const std::string &get_port() const { return m_port; };

			using abstract_http_client::set_server;

			void set_server(std::string host, std::string port) override;
			void set_auto_connect(bool auto_connect) override;

			template<typename F>
			void set_connector(F connector)
			{
				LOCK_RECURSIVE_MUTEX(m_lock);
				m_net_client.set_connector(std::move(connector));
			}

      bool connect(std::chrono::milliseconds timeout) override;
			bool disconnect() override;
			bool is_connected() override;

			//---------------------------------------------------------------------------
			virtual bool handle_target_data(std::string& piece_of_transfer) override
			{
				LOCK_RECURSIVE_MUTEX(m_lock);
				m_response_info.m_body += piece_of_transfer;
        piece_of_transfer.clear();
				return true;
			}
			//---------------------------------------------------------------------------
			virtual bool on_header(const http_response_info &headers)
      {
        return true;
      }

			bool invoke_get(const std::string_view uri, std::chrono::milliseconds timeout, const std::string& body = std::string(), const http_response_info** ppresponse_info = NULL, const fields_list& additional_params = fields_list()) override;
			bool invoke(const std::string_view uri, const std::string_view method, const std::string& body, std::chrono::milliseconds timeout, const http_response_info** ppresponse_info = NULL, const fields_list& additional_params = fields_list()) override;
			bool invoke_post(const std::string_view uri, const std::string& body, std::chrono::milliseconds timeout, const http_response_info** ppresponse_info = NULL, const fields_list& additional_params = fields_list()) override;
			bool test(const std::string &s, std::chrono::milliseconds timeout);
			uint64_t get_bytes_sent() const override;
			uint64_t get_bytes_received() const override;
			void wipe_response();
			//---------------------------------------------------------------------------
		private:
			bool handle_reciev(std::chrono::milliseconds timeout);
      bool handle_header(std::string& recv_buff, bool& need_more_data);
      bool handle_body_content_len(std::string& recv_buff, bool& need_more_data);
      bool handle_body_connection_close(std::string& recv_buff, bool& need_more_data);
			bool is_hex_symbol(char ch);
      bool get_len_from_chunk_head(const std::string &chunk_head, size_t& result_size);
      bool get_chunk_head(std::string& buff, size_t& chunk_size, bool& is_matched);
      bool handle_body_body_chunked(std::string& recv_buff, bool& need_more_data);
			bool parse_header(http_header_info& body_info, const std::string& m_cache_to_process);
			bool analize_first_response_line();
      bool set_reply_content_encoder();
      bool analize_cached_header_and_invoke_state();
      bool is_connection_close_field(const std::string& str);
      bool is_multipart_body(const http_header_info& head_info, std::string& boundary);
		};
		typedef http_simple_client_template http_simple_client;
	}
}
}
