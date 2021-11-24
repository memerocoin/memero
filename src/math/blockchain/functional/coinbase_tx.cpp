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


#include "coinbase_tx.hpp"

#include "tools/epee/include/logging.hpp"
#include "consensus/consensus.hpp"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "math/blockchain/coinbase_tx"

namespace cryptonote {

std::optional<coinbase_tx> maybe_coinbase_tx(const transaction& tx) {
  LOG_ERROR_AND_RETURN_UNLESS
    (
      tx.version == 2
      , {}
      , "Invalid coinbase transaction version"
      );

  LOG_ERROR_AND_RETURN_UNLESS
    (
      tx.ringct.type == rct::RCTTypeNull
      , {}
      , "Wrong rct type in miner tx"
      );

  const auto maybe_vin = consensus::rule_22_coinbase_tx_should_have_only_one_input(tx.vin);
  LOG_ERROR_AND_RETURN_UNLESS
    ( maybe_vin
      , {}
      , "Wrong number of inputs"
      );

  const auto maybe_input = consensus::rule_23_coinbase_tx_input_type_should_be_gen(*maybe_vin);
  LOG_ERROR_AND_RETURN_UNLESS
    (
      maybe_input
      , {}
      , "input has the wrong type"
      );

  const auto input = *maybe_input;

  const auto maybe_outputs = check_tx_output_points(tx);
  LOG_ERROR_AND_RETURN_UNLESS
    (
     maybe_outputs
     , {}
     , "invalid outputs"
     );

  const std::vector<crypto::public_key> output_public_keys = *maybe_outputs;

  std::vector<coinbase_output> outputs;
  std::transform
    (
      tx.vout.begin()
      , tx.vout.end()
      , output_public_keys.begin()
      , std::back_inserter(outputs)
      , [](const auto& x, const auto& y) -> coinbase_output {
        return {
          x.amount
          , y
        };
      }
      );


  const tx_common common = {
    tx.unlock_height
    , tx.extra
  };

  const coinbase_tx x = {
    { common }
    , input.height
    , outputs
  };

  return x;
}

}

