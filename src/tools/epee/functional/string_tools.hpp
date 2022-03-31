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
#include "tools/epee/functional/blob.hpp"

#include <sstream>

namespace epee
{
namespace string_tools
{
  epee::blob::data string_to_blob(const std::string_view s);
  epee::blob::view string_view_to_blob_view(const std::string_view s);
  std::string blob_to_string(const epee::blob::span s);
  std::string buff_to_hex_nodelimer(const std::string& src);

	std::string get_ip_string_from_int32(uint32_t ip);
	std::string num_to_string_fast(int64_t val);

  //---------------------------------------------------------------------
  template<typename T>
  std::string to_string_hex(const T &val)
  {
    static_assert(std::is_arithmetic<T>::value, "only arithmetic types");
    std::stringstream ss;
    ss << std::hex << val;
    std::string s;
    ss >> s;
    return s;
  }
            

  //----------------------------------------------------------------------------
	bool compare_no_case(const std::string& str1, const std::string& str2);

  //----------------------------------------------------------------------------
  template<class t_pod_type>
  std::string pod_to_hex(const t_pod_type& s)
  {
    static_assert(std::is_standard_layout<t_pod_type>(), "expected standard layout type");
    return hex::encode_to_hex(pod_to_span(s));
  }

  //----------------------------------------------------------------------------
  template<class t_pod_type>
  std::optional<t_pod_type> hex_to_pod
  (const std::string_view hex_str)
  {
    static_assert(std::is_standard_layout<t_pod_type>(), "expected standard layout type");
    const auto maybe_blob = hex::decode_from_hex_to_blob(hex_str);
    if (!maybe_blob) return {};

    return epee::span_to_pod<t_pod_type>(*maybe_blob);
  }

} // stringtools
} // epee
