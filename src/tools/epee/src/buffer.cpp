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

#include "tools/epee/include/net/buffer.h"

#include "tools/epee/include/logging.hpp"




namespace epee
{
namespace net_utils
{

  void buffer::append(const void *data, size_t sz) {
    storage.append((uint8_t*)data, sz);
  }

  void buffer::erase(size_t sz) {
    NET_BUFFER_LOG("erasing " << sz << "/" << size());
    LOG_ERROR_AND_THROW_UNLESS(offset + sz <= storage.size(), "erase: sz too large");
    offset += sz;
    if (offset == storage.size()) {
      storage.clear();
      offset = 0;
    }
  }

  std::span<const uint8_t> buffer::span(size_t sz) const {
    LOG_ERROR_AND_THROW_UNLESS(sz <= size(), "span is too large");
    return std::span<const uint8_t>(storage).subspan(offset, sz);
  }

  epee::blob::data buffer::carve(size_t sz) {
    LOG_ERROR_AND_THROW_UNLESS(sz <= size(), "span is too large");
    const epee::blob::data x = storage.substr(offset, sz);
    offset += sz;
    return x;
  }

  size_t buffer::size() const {
    return storage.size() - offset;
  }

}
}
