// Copyright (c) 2020, fuwa, The LOLnero Project
// License: BSD3

#pragma once

#include <cstdlib>
#include <inttypes.h>

namespace config
{
  namespace lol
  {
    constexpr std::string_view CRYPTONOTE_NAME = "lolnero";
    constexpr size_t BLOCKS_SYNCHRONIZING_SIZE = 100;
    constexpr std::string_view RPC_DEFAULT_HOST = "localhost";
    constexpr std::string_view CRYPTONOTE_BLOCKCHAINDATA_FILENAME = "data.mdb";
    constexpr std::string_view CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME = "lock.mdb";
    constexpr std::string_view P2P_NET_DATA_FILENAME = "p2pstate.bin";

    constexpr size_t mixin = 31;
    constexpr size_t ring_size = 32;
    constexpr uint8_t constant_hf_version = 17;
    constexpr uint64_t constant_hf_height = 0;
    constexpr time_t constant_hf_time = 1600576524;
    constexpr size_t max_connections_per_address = 2;
    constexpr uint64_t min_block_weight = 128 * 1024; // 128 kB
    constexpr uint64_t max_tx_weight = 128 * 1024; // 128 kB
    constexpr std::string_view ASCII_OUTPUT_MAGIC = "LolneroAsciiDataV1";
    constexpr size_t genesis_tx_version = 1;
    constexpr size_t tx_version = 2;
  }
}
