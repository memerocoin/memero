/*

Copyright 2021 fuwa

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.


Parts of this file are originally 
Copyright (c) 2014-2020, The Monero Project

see: etc/other-licenses/monero/LICENSE

*/

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
    void encode_to_hex_iterator(T&& out, const std::span<const std::uint8_t> src)
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
  template<typename T>
  T encode_to_hex_t(const std::span<const std::uint8_t> src)
  {
    if (std::numeric_limits<std::size_t>::max() / 2 < src.size())
      throw std::range_error("hex_view::to_string exceeded maximum size");

    T out{};
    out.resize(src.size() * 2);
    encode_to_hex_iterator(out.data(), src); // can't see the non const version in wipeable_string??
    return out;
  }

  std::string encode_to_hex(const std::span<const std::uint8_t> src) {
    return encode_to_hex_t<std::string>(src);
  }

  void encode_to_hex_stream(std::ostream& out, const std::span<const std::uint8_t> src)
  {
    encode_to_hex_iterator(std::ostreambuf_iterator<char>{out}, src);
  }

  void encode_to_hex_stream_formatted(std::ostream& out, const std::span<const std::uint8_t> src)
  {
    out.put('<');
    encode_to_hex_stream(out, src);
    out.put('>');
  }

  bool decode_from_hex_unchecked(std::uint8_t* dst, const std::string_view s) noexcept
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

  std::optional<epee::blob::data> decode_from_hex_to_blob(const std::string_view src) {
    epee::blob::data out;
    out.resize(src.size() / 2);
    const bool r = decode_from_hex_unchecked(out.data(), src);
    if (r) {
      return out;
    } else {
      return {};
    }
  }

  bool decode_from_hex_to_string(std::string& res, const std::string_view s)
  {
    const auto r = decode_from_hex_to_blob(s);
    if (r) {
      res = ::epee::string_tools::blob_to_string(*r);
      return true;
    } else {
      return false;
    }
  }

} // hex
}
