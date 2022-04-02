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

namespace epee
{
namespace net_utils
{

  void buffer::append_raw(const void *data, size_t sz) {
    append(epee::blob::span((uint8_t*)data, sz));
  }

  void buffer::append(const epee::blob::span x) {
    storage.append(x.data(), x.size());
  }

  void buffer::erase(size_t sz) {
    storage.erase(0, sz);
  }

  std::span<const uint8_t> buffer::span(size_t sz) const {
    return std::span<const uint8_t>(storage).subspan(0, sz);
  }

  epee::blob::data buffer::carve(size_t sz) {
    const epee::blob::data x = storage.substr(0, sz);
    erase(sz);
    return x;
  }

  size_t buffer::size() const {
    return storage.size();
  }

}
}
