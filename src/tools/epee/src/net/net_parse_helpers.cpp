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




#include "tools/epee/include/net/net_parse_helpers.h"

#include "tools/epee/include/logging.hpp"




namespace epee
{
namespace net_utils
{

  bool parse_uri_query(const std::string& query, std::list<std::pair<std::string, std::string> >& params)
  {
    enum state
    {
      st_param_name,
      st_param_val
    };
    state st = st_param_name;
    std::string::const_iterator start_it = query.begin();
    std::pair<std::string, std::string> e;
    for(std::string::const_iterator it = query.begin(); it != query.end(); it++)
    {
      switch(st)
      {
      case st_param_name:
        if(*it == '=')
        {
          e.first.assign(start_it, it);
          start_it = it;++start_it;
          st = st_param_val;
        }
        break;
      case st_param_val:
        if(*it == '&')
        {
          e.second.assign(start_it, it);
          start_it = it;++start_it;
          params.push_back(e);
          e.first.clear();e.second.clear();
          st = st_param_name;
        }
        break;
      default:
        LOG_ERROR("Unknown state " << (int)st);
        return false;
      }
    }
    if(st == st_param_name)
    {
      if(start_it != query.end())
      {
        e.first.assign(start_it, query.end());
        params.push_back(e);
      }
    }else
    {
      if(start_it != query.end())
        e.second.assign(start_it, query.end());

      if(e.first.size())
        params.push_back(e);
    }
    return true;
  }

  bool parse_uri(const std::string uri, http::uri_content& content)
  {
    content.m_query_params.clear();
    STATIC_REGEXP_EXPR_1(rexp_match_uri, "^([^?#]*)(\\?([^#]*))?(#(.*))?", std::regex::icase );

    std::smatch result;
    if(!(std::regex_search(uri, result, rexp_match_uri) && result[0].matched))
    {
      LOG_PRINT_L1("[PARSE URI] regex not matched for uri: " + uri);
      content.m_path = uri;
      return true;
    }
    if(result[1].matched)
    {
      content.m_path = result[1];
    }
    if(result[3].matched)
    {
      content.m_query = result[3];
    }
    if(result[5].matched)
    {
      content.m_fragment = result[5];
    }
    if(content.m_query.size())
    {
      parse_uri_query(content.m_query, content.m_query_params);
    }
    return true;
  }

}
}
