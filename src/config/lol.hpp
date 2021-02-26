// Copyright (c) 2020, fuwa, The LOLnero Project
// License: BSD3

#pragma once

#include <cstdlib>
#include <inttypes.h>

namespace config
{
  namespace lol
  {
    const size_t mixin = 31;
    const size_t ring_size = 32;
    const uint8_t constant_hf_version = 17;
    const uint64_t constant_hf_height = 0;
    const time_t constant_hf_time = 1600576524;
    const size_t max_connections_per_address = 2;
    constexpr uint64_t max_block_weight = 4 * 1024 * 1024; // 4 MB
    const std::string ASCII_OUTPUT_MAGIC = "LolneroAsciiDataV1";
    const size_t tx_version = 2;
  }
}
