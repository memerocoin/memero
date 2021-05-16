// Copyright (c) 2020, fuwa, The LOLnero Project
// License: BSD3

#pragma once

#include <cstdlib>
#include <inttypes.h>
#include <string>
#include <chrono>

namespace constant
{
  // MONEY_SUPPLY - total number coins to be generated
  constexpr uint64_t MONEY_SUPPLY = (uint64_t)(-1);

  // COIN - number of smallest units in one coin
  constexpr uint64_t COIN = 100000000000u; // pow(10, 11)


  constexpr uint64_t DIFFICULTY_TARGET_IN_SECONDS = 300;
  constexpr uint64_t DIFFICULTY_WINDOW_IN_BLOCKS = 144;
  constexpr uint64_t DIFFICULTY_BLOCKS_COUNT = DIFFICULTY_WINDOW_IN_BLOCKS + 1;


  constexpr uint64_t CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V2 = 300*2;
  constexpr uint64_t CRYPTONOTE_MEMPOOL_TX_LIVETIME = 86400 * 3; //seconds, three days
  constexpr uint64_t CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME = 604800; //seconds, one week
  constexpr std::chrono::seconds CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE(1);

  constexpr uint64_t CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE = 600;
  constexpr size_t CRYPTONOTE_MAX_TX_PER_BLOCK = 0x10000000;

  constexpr uint64_t CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS = 1;
  constexpr uint64_t CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2 =
    DIFFICULTY_TARGET_IN_SECONDS * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS;



  constexpr uint32_t DEFAULT_MIN_OUTPUT_COUNT = 5;
  constexpr uint64_t DEFAULT_MIN_OUTPUT_VALUE = 2 * COIN;

  constexpr uint64_t FEE_PER_BYTE = 300000;
  constexpr size_t PER_KB_FEE_QUANTIZATION_DECIMALS = 8;

  constexpr size_t BULLETPROOF_MAX_OUTPUTS = 16;



  //by default, blocks ids count in synchronizing
  constexpr size_t BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT = 10000;
  //max blocks ids count in synchronizing
  constexpr size_t BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT = 25000;



  constexpr size_t DEFAULT_TXPOOL_MAX_WEIGHT = 648000000; // 3 days at 300000, in bytes
  constexpr size_t BLOCKS_SYNCHRONIZING_SIZE = 100;
  constexpr size_t BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2 = 11;


  constexpr uint64_t RPC_IP_FAILS_BEFORE_BLOCK = 3;
  constexpr size_t COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT = 1000;

  constexpr uint64_t OLD_AGE_WALLET_IN_BLOCKS = 30 * 86400 / DIFFICULTY_TARGET_IN_SECONDS; // 30 days
  constexpr uint32_t DEFAULT_RPC_AUTO_REFRESH_PERIOD_IN_SECONDS = 20;

  constexpr uint64_t LEVIN_SIGNATURE = 0x0101010101012101LL; //Bender's nightmare
  constexpr size_t LEVIN_DEFAULT_TIMEOUT_PRECONFIGURED = 0;
  constexpr uint64_t LEVIN_INITIAL_MAX_PACKET_SIZE = 256*1024;     // 256 KiB before handshake
  constexpr uint64_t LEVIN_DEFAULT_MAX_PACKET_SIZE = 100000000;      //100MB by default after handshake

}

namespace config
{
  // Hash domain separators
  constexpr char HASH_KEY_BULLETPROOF_EXPONENT[] = "bulletproof";
  constexpr char HASH_KEY_SUBADDRESS[] = "SubAddr";
  constexpr unsigned char HASH_KEY_WALLET = 0x8c;
  constexpr unsigned char HASH_KEY_WALLET_CACHE = 0x8d;
  constexpr unsigned char HASH_KEY_MEMORY = 'k';
  constexpr unsigned char HASH_KEY_TXPROOF_V2[] = "TXPROOF_V2";
  constexpr unsigned char HASH_KEY_CLSAG_ROUND[] = "CLSAG_round";
  constexpr unsigned char HASH_KEY_CLSAG_AGG_0[] = "CLSAG_agg_0";
  constexpr unsigned char HASH_KEY_CLSAG_AGG_1[] = "CLSAG_agg_1";
  constexpr char HASH_KEY_MESSAGE_SIGNING[] = "LolneroMessageSignature";

  namespace lol
  {
    constexpr std::string_view CRYPTONOTE_NAME = "lolnero";
    constexpr std::string_view RPC_DEFAULT_HOST = "localhost";
    constexpr std::string_view BLOCKCHAIN_DATABASE_FILENAME = "data.mdb";
    constexpr std::string_view BLOCKCHAIN_DATABASE_LOCK_FILENAME = "lock.mdb";
    constexpr std::string_view P2P_NET_DATA_FILENAME = "p2pstate.bin";

    constexpr size_t mixin = 31;
    constexpr size_t ring_size = 32;
    constexpr uint8_t constant_hf_version = 17;
    constexpr uint64_t constant_hf_height = 0;
    constexpr size_t constant_transaction_version = 2;
    constexpr time_t constant_hf_time = 1600576524;
    constexpr size_t max_connections_per_address = 2;
    constexpr uint64_t min_block_weight = 128 * 1024; // 128 kB
    constexpr uint64_t max_tx_weight = 128 * 1024; // 128 kB
    constexpr std::string_view ASCII_OUTPUT_MAGIC = "LolneroAsciiDataV1";
    constexpr size_t genesis_tx_version = 1;
    constexpr size_t tx_version = 2;

    constexpr size_t SUBADDRESS_LOOKAHEAD_MAJOR = 50;
    constexpr size_t SUBADDRESS_LOOKAHEAD_MINOR = 400;
  }
}
