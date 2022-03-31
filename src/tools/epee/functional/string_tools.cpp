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

#include "string_tools.hpp"

#include <arpa/inet.h>
#include <boost/algorithm/string/predicate.hpp>

namespace epee
{
namespace string_tools
{
  //----------------------------------------------------------------------------
  epee::blob::view string_view_to_blob_view(const std::string_view s) {
    return std::basic_string_view((uint8_t*)s.data(), s.size());
  };
  //----------------------------------------------------------------------------
  epee::blob::data string_to_blob(const std::string_view s) {
    return std::basic_string((uint8_t*)s.data(), s.size());
  };
  //----------------------------------------------------------------------------
  std::string blob_to_string(const epee::blob::span s) {
    return std::string((char*)s.data(), s.size());
  };
  //----------------------------------------------------------------------------
  std::string buff_to_hex_nodelimer(const std::string_view src)
  {
    return hex::encode_to_hex(string_to_blob(src));
  }
	std::string num_to_string_fast(const int64_t val)
	{
    return std::to_string(val);
	}
	//----------------------------------------------------------------------------
	bool compare_no_case(const std::string_view str1, const std::string_view str2)
	{
		return !boost::iequals(str1, str2);
	}

  std::string get_ip_string_from_int32(const uint32_t ip)
  {
    in_addr adr;
    adr.s_addr = ip;
    const char* pbuf = inet_ntoa(adr);
    if(pbuf)
      return pbuf;
    else
      return "[failed]";
  }

} // string_tools
} // epee
