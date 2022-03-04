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

#pragma once


#include "tools/epee/include/span.h"
#include "tools/epee/include/blob.hpp"

#include <span>
#include <optional>
#include <string>

namespace epee
{
namespace hex
{
  std::string encode_to_hex(const std::span<const std::uint8_t> src);
  std::string encode_to_hex_formatted
  (const std::span<const std::uint8_t> src);

  //! Append `src` as hex to `out`.
  void encode_to_hex_stream
    (std::ostream& out, const std::span<const std::uint8_t> src);

  //! Append `< + src + >` as hex to `out`.
  void encode_to_hex_stream_formatted
    (std::ostream& out, const std::span<const std::uint8_t> src);

  std::optional<epee::blob::data> decode_from_hex_to_blob
    (const std::string_view src);

  std::optional<std::string> decode_from_hex_to_string
    (const std::string_view src);

  std::optional<epee::blob::data> decode_from_hex_to_blob
    (const std::string_view src);
};
}
