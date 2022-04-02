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

*/

#pragma once

#include "tools/epee/functional/blob.hpp"

#include <span>
#include <cstdint>
#include <string>




//#define NET_BUFFER_LOG(x) LOG_DEBUG(x)
#define NET_BUFFER_LOG(x) ((void)0)

namespace epee
{
namespace net_utils
{
class buffer
{
public:
  buffer(size_t reserve = 0): offset(0) { storage.reserve(reserve); }

  void append(const void *data, size_t sz);
  void erase(size_t sz);
  std::span<const uint8_t> span(size_t sz) const;
  // carve must keep the data in scope till next call, other API calls (such as append, erase) can invalidate the carved buffer
  epee::blob::data carve(size_t sz);
  size_t size() const;

private:
  epee::blob::data storage;
  size_t offset;
};
}
}
