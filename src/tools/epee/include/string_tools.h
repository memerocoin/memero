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

#include "tools/epee/functional/hex.hpp"
#include "tools/epee/functional/span.hpp"
#include "tools/epee/functional/blob.hpp"
#include "tools/epee/include/storages/parserse_base_utils.h"

#include "tools/epee/functional/string_tools.hpp"

#include <filesystem>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/lexical_cast.hpp>



namespace epee
{
namespace string_tools
{
  bool parse_hexstr_to_binbuff(const std::string_view s, std::string& res);

  //----------------------------------------------------------------------------
  template<class XType>
  bool get_xtype_from_string(XType& val, const std::string& str_id)
  {
    if (std::is_integral<XType>::value && !std::numeric_limits<XType>::is_signed && !std::is_same<XType, bool>::value)
    {
      for (char c : str_id)
      {
        if (!epee::misc_utils::parse::isdigit(c))
          return false;
      }
    }

    try
    {
      val = boost::lexical_cast<XType>(str_id);
      return true;
    }
    catch(const std::exception& /*e*/)
    {
      //const char* pmsg = e.what();
      return false;
    }
    catch(...)
    {
      return false;
    }

    return true;
  }
	//----------------------------------------------------------------------------
	template<class XType>
	bool xtype_to_string(const XType& val, std::string& str)
	{
		try
		{
			str = boost::lexical_cast<std::string>(val);
		}
		catch(...)
		{
			return false;
		}

		return true;
	}
	//----------------------------------------------------------------------------
	bool get_ip_int32_from_string(uint32_t& ip, const std::string& ip_str);
  bool parse_peer_from_string(uint32_t& ip, uint16_t& port, const std::string& addres);

  std::string pad_string(std::string s, size_t n, char c = ' ', bool prepend = false);

} // stringtools
} // epee
