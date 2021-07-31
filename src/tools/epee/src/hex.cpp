// Copyright (c) 2017-2020, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "tools/epee/include/hex.h"
#include "tools/epee/include/string_tools.h"
#include "tools/epee/include/storages/parserse_base_utils.h"

#include <limits>
#include <string>
#include <iostream>

namespace epee
{
  namespace
  {
    template<typename T>
    void write_hex(T&& out, const std::span<const std::uint8_t> src)
    {
      static constexpr const char hex[] = "0123456789abcdef";
      static_assert(sizeof(hex) == 17, "bad string size");
      for (const std::uint8_t byte : src)
      {
        *out = hex[byte >> 4];
        ++out;
        *out = hex[byte & 0x0F];
        ++out;
      }
    }
  }


namespace hex
{
  void buffer_unchecked(char* out, const std::span<const std::uint8_t> src) noexcept
  {
    return write_hex(out, src);
  }

  template<typename T>
  T convert(const std::span<const std::uint8_t> src)
  {
    if (std::numeric_limits<std::size_t>::max() / 2 < src.size())
      throw std::range_error("hex_view::to_string exceeded maximum size");

    T out{};
    out.resize(src.size() * 2);
    buffer_unchecked((char*)out.data(), src); // can't see the non const version in wipeable_string??
    return out;
  }

  std::string decode(const std::span<const std::uint8_t> src) {
    return convert<std::string>(src);
  }

  void append_decode(std::ostream& out, const std::span<const std::uint8_t> src)
  {
    write_hex(std::ostreambuf_iterator<char>{out}, src);
  }

  void append_decode_formatted(std::ostream& out, const std::span<const std::uint8_t> src)
  {
    out.put('<');
    append_decode(out, src);
    out.put('>');
  }

  bool to_buffer_unchecked(std::uint8_t* dst, const std::string_view s) noexcept
  {
    if (s.size() % 2 != 0)
      return false;

    const unsigned char *src = (const unsigned char *)s.data();
    for(size_t i = 0; i < s.size(); i += 2)
    {
      int tmp = *src++;
      tmp = epee::misc_utils::parse::isx[tmp];
      if (tmp == 0xff) return false;
      int t2 = *src++;
      t2 = epee::misc_utils::parse::isx[t2];
      if (t2 == 0xff) return false;
      *dst++ = (tmp << 4) | t2;
    }

    return true;
  }

  bool to_buffer(std::span<std::uint8_t> out, const std::string_view src) noexcept
  {
    if (src.size() / 2 != out.size())
      return false;
    return to_buffer_unchecked(out.data(), src);
  }

  std::optional<epee::blob::data> to_blob(const std::string_view src) {
    epee::blob::data out;
    out.resize(src.size() / 2);
    const bool r = to_buffer_unchecked(out.data(), src);
    if (r) {
      return out;
    } else {
      return {};
    }
  }

  bool to_string(std::string& res, const std::string_view s)
  {
    const auto r = to_blob(s);
    if (r) {
      res = ::epee::string_tools::blob_to_string(*r);
      return true;
    } else {
      return false;
    }
  }

} // hex
}
