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

#pragma once

#include <string>
#include <cstring>
#include <cstdint>
#include <span>
#include <optional>
#include <type_traits>

namespace epee
{

  template<typename T>
  constexpr bool has_padding() noexcept
  {
    return !std::is_standard_layout<T>() || alignof(T) != 1;
  }

  template<typename T>
  constexpr std::span<const std::uint8_t> pod_to_span(const T& src) noexcept
  {
    static_assert(!std::is_empty<T>(), "empty types will not work -> sizeof == 1");
    static_assert(!has_padding<T>(), "source type may have padding");
    return std::span<const std::uint8_t>((const uint8_t*)(&src), sizeof(T));
  }

  template<typename T>
  constexpr std::optional<T> span_to_pod(const std::span<const std::uint8_t> src) noexcept
  {
    static_assert(!std::is_empty<T>(), "empty types will not work -> sizeof == 1");
    static_assert(!has_padding<T>(), "source type may have padding");

    if (src.size() < sizeof(T)) {
      return {};
    }

    T x;

    std::memcpy
      (
       std::addressof(x)
       , src.data()
       , sizeof(T)
       );

    return x;
  }
}
