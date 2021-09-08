// Copyright (c) 2014-2020, The Monero Project
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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "cryptonote_tx_utils.h"


#include "tools/epee/include/string_tools.h"

#include "math/crypto/controller/random.hpp"

#include "math/ringct/pseudo_functional/rctSigs.hpp"
#include "math/ringct/controller/rctSigGen.hpp"

#include "wallet/device/functional/device_default.hpp"



namespace cryptonote
{
  //---------------------------------------------------------------
  bool construct_tx_and_get_tx_key
  (
   const account_keys& sender_account_keys
   , const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses
   , const std::vector<tx_source_entry>& sources
   , const std::vector<tx_destination_entry>& destinations
   , const std::optional<cryptonote::account_public_address>& change_addr
   , const std::vector<uint8_t> &extra
   , const uint64_t unlock_time
   , transaction& tx
   , crypto::secret_key &tx_key
   , std::vector<crypto::secret_key> &additional_tx_keys
   )
  {
    tx_key = cryptonote::keypair::generate().sec;
    try {
      // figure out if we need to make additional tx pubkeys
      const auto[num_stdaddresses, num_subaddresses, single_dest_subaddress] =
        classify_addresses(destinations, change_addr);

      bool need_additional_txkeys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);
      if (need_additional_txkeys)
      {
        additional_tx_keys.clear();
        additional_tx_keys.resize(destinations.size());
        std::generate(additional_tx_keys.begin(), additional_tx_keys.end(),
                      []() {
                        return keypair::generate().sec;
                      });
      }

      const auto& r = construct_tx_with_tx_key(sender_account_keys, subaddresses, sources, destinations, change_addr, extra, unlock_time, tx_key, additional_tx_keys);
      if (r) {
        tx = *r;
        return true;
      }

      return false;
    } catch(...) {
      throw;
    }
  }

  //---------------------------------------------------------------
  std::optional<transaction> construct_miner_tx
  (
   const size_t height
   , const size_t current_block_weight
   , const uint64_t fee
   , const account_public_address &miner_address
   )
  {
    transaction tx;

    tx.vin.clear();
    tx.vout.clear();
    tx.extra.clear();

    keypair txkey = keypair::generate();
    add_tx_pub_key_to_extra(tx, txkey.pub);
    if (!sort_tx_extra(tx.extra, tx.extra))
      return {};

    txin_gen in;
    in.height = height;

    if(!check_block_weight(static_cast<uint64_t>(height), current_block_weight))
    {
      LOG_PRINT_L0("Block is too big");
      return {};
    }
    uint64_t block_reward = get_block_reward();

    block_reward += fee;

    std::optional<crypto::tx_ecdh_shared_secret> tx_shared_secret =
      crypto::derive_tx_ecdh_shared_secret(miner_address.m_view_public_key, txkey.sec);

    LOG_ERROR_AND_RETURN_UNLESS
      (
       tx_shared_secret
       , {}
       , "while creating outs: failed to derive_tx_ecdh_shared_secret("
       << miner_address.m_view_public_key << ", " << txkey.sec << ")"
       );

    const std::optional<crypto::public_key> out_eph_public_key =
      crypto::derive_tx_output_public_key_from_spend_public_key(*tx_shared_secret, 0, miner_address.m_spend_public_key);
    LOG_ERROR_AND_RETURN_UNLESS
      (
       out_eph_public_key
       , {}
       , "while creating outs: failed to derive_tx_output_public_key_from_spend_public_key("
       << *tx_shared_secret << ", " << 0 << ", "
       << miner_address.m_spend_public_key << ")"
       );

    txout_to_key tk;
    tk.key = *out_eph_public_key;

    tx_out out;
    out.amount = block_reward;
    out.target = tk;
    tx.vout.push_back(out);

    tx.version = 2;

    //lock
    tx.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
    tx.vin.push_back(in);

    //LOG_PRINT("MINER_TX generated ok, block_reward=" << print_money(block_reward) << "("  << print_money(block_reward - fee) << "+" << print_money(fee)
    //  << "), current_block_size=" << current_block_size << ", already_generated_coins=" << already_generated_coins << ", tx_id=" << get_transaction_hash(tx), LOG_LEVEL_2);
    return tx;
  }

}
