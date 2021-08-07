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

#include "tools/epee/include/string_tools.h"

#include <arpa/inet.h>

namespace epee
{
namespace string_tools
{
  //----------------------------------------------------------------------------
  epee::blob::view string_view_to_blob_view(const std::string_view s) {
    return std::basic_string_view((uint8_t*)s.data(), s.size());
  };
  //----------------------------------------------------------------------------
  epee::blob::data string_to_blob(const std::string& s) {
    return std::basic_string((uint8_t*)s.data(), s.size());
  };
  //----------------------------------------------------------------------------
  std::string blob_to_string(const epee::blob::data& s) {
    return std::string((char*)s.data(), s.size());
  };
  //----------------------------------------------------------------------------
  std::string buff_to_hex_nodelimer(const std::string& src)
  {
    return hex::decode(string_to_blob(src));
  }
  //----------------------------------------------------------------------------
  bool parse_hexstr_to_binbuff(const std::string_view s, std::string& res)
  {
    return hex::to_string(res, s);
  }
  //----------------------------------------------------------------------------
  bool parse_peer_from_string(uint32_t& ip, uint16_t& port, const std::string& addres)
  {
    //parse ip and address
    std::string::size_type p = addres.find(':');
    std::string ip_str, port_str;
    if(p == std::string::npos)
    {
      port = 0;
      ip_str = addres;
    }
    else
    {
      ip_str = addres.substr(0, p);
      port_str = addres.substr(p+1, addres.size());
    }

    if(!get_ip_int32_from_string(ip, ip_str))
    {
      return false;
    }

    if(p != std::string::npos && !get_xtype_from_string(port, port_str))
    {
      return false;
    }
    return true;
  }

	std::string num_to_string_fast(int64_t val)
	{
		/*
		char  buff[30] = {0};
		i64toa_s(val, buff, sizeof(buff)-1, 10);
		return buff;*/
		return boost::lexical_cast<std::string>(val);
	}
	//----------------------------------------------------------------------------
	bool compare_no_case(const std::string& str1, const std::string& str2)
	{
		return !boost::iequals(str1, str2);
	}
	//----------------------------------------------------------------------------
	bool trim_left(std::string& str)
	{
		for(std::string::iterator it = str.begin(); it!= str.end() && isspace(static_cast<unsigned char>(*it));)
			str.erase(str.begin());

		return true;
	}
	//----------------------------------------------------------------------------
	bool trim_right(std::string& str)
	{

		for(std::string::reverse_iterator it = str.rbegin(); it!= str.rend() && isspace(static_cast<unsigned char>(*it));)
			str.erase( --((it++).base()));

		return true;
	}
	//----------------------------------------------------------------------------
	std::string& trim(std::string& str)
	{

		trim_left(str);
		trim_right(str);
		return str;
	}
  //----------------------------------------------------------------------------
  std::string trim(const std::string& str_)
  {
    std::string str = str_;
    trim_left(str);
    trim_right(str);
    return str;
  }
  //----------------------------------------------------------------------------
  std::string pad_string(std::string s, size_t n, char c, bool prepend)
  {
    if (s.size() < n)
    {
      if (prepend)
        s = std::string(n - s.size(), c) + s;
      else
        s.append(n - s.size(), c);
    }
    return s;
  }

  std::string get_ip_string_from_int32(uint32_t ip)
  {
    in_addr adr;
    adr.s_addr = ip;
    const char* pbuf = inet_ntoa(adr);
    if(pbuf)
      return pbuf;
    else
      return "[failed]";
  }
  //----------------------------------------------------------------------------
  bool get_ip_int32_from_string(uint32_t& ip, const std::string& ip_str)
  {
    ip = inet_addr(ip_str.c_str());
    if(INADDR_NONE == ip)
      return false;

    return true;
  }
  //----------------------------------------------------------------------------
  bool validate_hex(uint64_t length, const std::string& str)
  {
    if (str.size() != length)
      return false;
    for (char c: str)
      if (!isxdigit(c))
        return false;
    return true;
  }

  std::vector<uint8_t> hex_to_vector_filtered(const std::string_view src)
  {
    std::string s(src);
    constexpr std::string_view allowed = "0123456789abcdefABCDEF";

    s.erase(std::remove_if
            (
             s.begin()
             , s.end(),
             [allowed](const char c) {
               return allowed.find(c) == std::string::npos;
             }
             ),
            s.end());

    const std::optional<::epee::blob::data> r = hex::to_blob(s);
    std::vector<uint8_t> v;
    if (r) {
      const auto str = *r;
      std::copy( str.begin(), str.end(), std::back_inserter(v));
    }
    return v;
  }
} // string_tools
} // epee
