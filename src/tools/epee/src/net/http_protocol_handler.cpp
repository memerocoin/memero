// Copyright (c) 2021, The Lolnero Project
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

#include "tools/epee/include/net/http_protocol_handler.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net.http"

namespace epee
{
namespace net_utils
{
	namespace http
	{
		bool match_boundary(const std::string& content_type, std::string& boundary)
		{
			STATIC_REGEXP_EXPR_1(rexp_match_boundary, "boundary=(.*?)(($)|([;\\s,]))", std::regex::icase );
			//											        1
			std::smatch result;
			if(std::regex_search(content_type, result, rexp_match_boundary) && result[0].matched)
			{
				boundary = result[1];
				return true;
			}

			return false;
		}

	  bool parse_header(std::string::const_iterator it_begin, std::string::const_iterator it_end, multipart_entry& entry)
		{
			STATIC_REGEXP_EXPR_1(rexp_mach_field,
				"\n?((Content-Disposition)|(Content-Type)"
				//  12                     3
				"|([\\w-]+?)) ?: ?((.*?)(\r?\n))[^\t ]",
				//4               56    7
				std::regex::icase );

			std::smatch		result;
			std::string::const_iterator it_current_bound = it_begin;
			std::string::const_iterator it_end_bound = it_end;

			//lookup all fields and fill well-known fields
			while( std::regex_search( it_current_bound, it_end_bound, result, rexp_mach_field) && result[0].matched)
			{
				const size_t field_val = 6;
				const size_t field_etc_name = 4;

				int i = 2; //start position = 2
				if(result[i++].matched)//"Content-Disposition"
					entry.m_content_disposition = result[field_val];
				else if(result[i++].matched)//"Content-Type"
					entry.m_content_type = result[field_val];
				else if(result[i++].matched)//e.t.c (HAVE TO BE MATCHED!)
					entry.m_etc_header_fields.push_back(std::pair<std::string, std::string>(result[field_etc_name], result[field_val]));
				else
				{
					LOG_ERROR("simple_http_connection_handler::parse_header() not matched last entry in:"<<std::string(it_current_bound, it_end));
				}

				it_current_bound = result[(int)result.size()-1].first;
			}
			return  true;
		}

		bool handle_part_of_multipart(std::string::const_iterator it_begin, std::string::const_iterator it_end, multipart_entry& entry)
		{
			std::string end_str = "\r\n\r\n";
			std::string::const_iterator end_header_it = std::search(it_begin, it_end, end_str.begin(), end_str.end());
			if(end_header_it == it_end)
			{
				//header not matched
				return false;
			}

			if(!parse_header(it_begin, end_header_it+4, entry))
			{
				LOG_ERROR("Failed to parse header:" << std::string(it_begin, end_header_it+2));
				return false;
			}

			entry.m_body.assign(end_header_it+4, it_end);

			return true;
		}

		bool parse_multipart_body(const std::string& content_type, const std::string& body, std::list<multipart_entry>& out_values)
		{
			//bool res = file_io_utils::load_file_to_string("C:\\public\\multupart_data", body);

			std::string boundary;
			if(!match_boundary(content_type, boundary))
			{
				MERROR("Failed to match boundary in content type: " << content_type);
				return false;
			}

			boundary+="\r\n";
			bool is_stop = false;
			bool first_step = true;

			std::string::const_iterator it_begin = body.begin();
			std::string::const_iterator it_end;
			while(!is_stop)
			{
				std::string::size_type pos = body.find(boundary, std::distance(body.begin(), it_begin));

				if(std::string::npos == pos)
				{
					is_stop = true;
					boundary.erase(boundary.size()-2, 2);
					boundary+= "--";
					pos = body.find(boundary, std::distance(body.begin(), it_begin));
					if(std::string::npos == pos)
					{
						MERROR("Error: Filed to match closing multipart tag");
						it_end = body.end();
					}else
					{
						it_end =  body.begin() + pos;
					}
				}else
					it_end =  body.begin() + pos;


				if(first_step && !is_stop)
				{
					first_step = false;
					it_begin = it_end + boundary.size();
					std::string temp = "\r\n--";
					boundary = temp + boundary;
					continue;
				}

				out_values.push_back(multipart_entry());
				if(!handle_part_of_multipart(it_begin, it_end, out_values.back()))
				{
					MERROR("Failed to handle_part_of_multipart");
					return false;
				}

				it_begin = it_end + boundary.size();
			}

			return true;
		}

    //--------------------------------------------------------------------------------------------
    bool analize_http_method(const std::smatch& result, http::http_method& method, int& http_ver_major, int& http_ver_minor)
    {
      LOG_ERROR_AND_RETURN_IF(result[0].matched, false, "simple_http_connection_handler::analize_http_method() assert failed...");
      if (!boost::conversion::try_lexical_convert<int>(result[11], http_ver_major))
        return false;
      if (!boost::conversion::try_lexical_convert<int>(result[12], http_ver_minor))
        return false;

      if(result[3].matched)
        method = http::http_method_options;
      else if(result[4].matched)
        method = http::http_method_get;
      else if(result[5].matched)
        method = http::http_method_head;
      else if(result[6].matched)
        method = http::http_method_post;
      else if(result[7].matched)
        method = http::http_method_put;
      else
        method = http::http_method_etc;

      return true;
    }

  }
}
}
