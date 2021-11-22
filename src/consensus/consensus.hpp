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

#include "math/ringct/functional/rctTypes.hpp"

#include <numeric>

using namespace rct;

namespace consensus {

  bool tx_output_amounts_should_not_overflow_amount_type
  (
   const rct_pointS outputs
   , const Bulletproof proof
   );

  bool tx_should_be_balanced
  (
   const rct_pointS inputs
   , const rct_pointS outputs
   , const amount_t fee
   );

  bool tx_input_should_be_from_a_ring
  (
   const crypto::hash message
   , const clsag sig
   , const output_public_dataS decoys
   , const rct_point pseudo_input_commit
   );


  consteval uint64_t get_coin_amount() {
    constexpr uint64_t COIN = 100000000000ull; // pow(10, 11)
    return COIN;
  }

  consteval uint64_t get_block_reward() {
    return get_coin_amount() * 300ull;
  }

  consteval bool block_reward_is_constant_300() {
    return get_block_reward() == get_coin_amount() * 300ull;
  }

  static_assert(block_reward_is_constant_300());

  consteval uint64_t get_minimum_block_size_bound() {
    constexpr uint64_t min_block_size = 128ull * 1024ull; // 128 kB
    return min_block_size;
  }

  constexpr uint64_t get_block_size_bound(const uint64_t height)
  {
    return std::max<uint64_t>(get_minimum_block_size_bound(), height);
  }

  constexpr bool block_size_should_be_bounded_by_height
  (
   const uint64_t height
   , const size_t block_size
   )
  {
    return block_size <= consensus::get_block_size_bound(height);
  }

  constexpr bool is_block_size_valid
  (
   const uint64_t height
   , const size_t block_size
   )
  {
    return block_size_should_be_bounded_by_height(height, block_size);
  }


  constexpr bool tx_input_decoys_offsets_should_not_be_zero_except_the_first_one
  (
   const std::span<const uint64_t> offsets
   )
  {
    if (offsets.empty()) return true;

    // Key offsets are relative increments of output indices in a blockchain
    // sorted by block height.
    // The first value can be 0. When it's 0, it references _the_ output of the coinbase
    // tx of the first block after the genesis block.
    //
    // We can verify this by playing with the `get_tx_outputs` daemon rpc call:
    //
    // echo '{"get_txid": true, "outputs":[{"index":0}]}' | http :45679/get_tx_outputs
    //
    // "outs": [
    //   {
    //     "height": 1,
    //     "key": "d2c5204259664c35c36c6d3743149359f494480ffb68b9c9885d9859201fecc5",
    //     "mask": "87050dabf5b23e8b79813f4ed76aa4add225dd2a5089af067da77ccb6ec55946",
    //     "txid": "370ae2825eb61aece7378f6a92fc22ebdc946cae751dabdf612524011a002340",
    //     "unlocked": true
    //   }
    // ],
    //
    // In other words, the tx output in genesis block is probably un-spendable, due to the
    // fact that it can not be included in a ring. :D

    return std::transform_reduce
      (
       std::next(offsets.begin())
       , offsets.end()
       , true
       , std::logical_and()
       , [](const auto& x) {
         return x != 0;
       }
       );
  }

}
