// Copyright (c) 2018, The Monero Project
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

#include "tools/epee/include/net/buffer.h"

#include "tools/epee/include/misc_log_ex.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net.buffer"

namespace epee
{
namespace net_utils
{

  void buffer::append(const void *data, size_t sz) {
    storage.append((uint8_t*)data, sz);
  }

  void buffer::erase(size_t sz) {
    NET_BUFFER_LOG("erasing " << sz << "/" << size());
    ASSERT_OR_LOG_THROW(offset + sz <= storage.size(), "erase: sz too large");
    offset += sz;
    if (offset == storage.size()) {
      storage.clear();
      offset = 0;
    }
  }

  std::span<const uint8_t> buffer::span(size_t sz) const {
    ASSERT_OR_LOG_THROW(sz <= size(), "span is too large");
    return std::span<const uint8_t>(storage).subspan(offset, sz);
  }

  std::span<const uint8_t> buffer::carve(size_t sz) {
    ASSERT_OR_LOG_THROW(sz <= size(), "span is too large");
    offset += sz;
    return std::span<const uint8_t>(storage).subspan(offset - sz, sz);
  }

  size_t buffer::size() const {
    return storage.size() - offset;
  }

}
}
