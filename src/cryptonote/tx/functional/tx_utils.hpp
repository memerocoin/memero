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

#pragma once

#include "cryptonote/basic/controller/format_utils.hpp"
#include "cryptonote/basic/controller/account.h"

#include "math/ringct/functional/rctOps.hpp"

namespace cryptonote
{
  struct tx_source_entry
  {
    typedef std::pair<uint64_t, rct::output_public_data> output_entry;

    std::vector<output_entry> outputs;  //index + key + optional ringct commitment
    size_t real_output;                 //index in outputs vector of real output_entry
    crypto::public_key real_out_tx_key; //incoming real tx public key
    std::vector<crypto::public_key> real_out_output_secret_keys; //incoming real tx additional public keys
    size_t real_output_in_tx_index;     //index in transaction outputs vector
    uint64_t amount;                    //money
    bool rct;                           //true if the output is rct
    rct::rct_scalar mask;                      //ringct amount mask

    // needed for test
    inline void push_output(uint64_t idx, const crypto::public_key &k, uint64_t amount) {
      outputs.push_back(std::make_pair(idx, rct::output_public_data({k, rct::dummyCommit(amount)})));
    }


    BEGIN_SERIALIZE_OBJECT()
      FIELD(outputs)
      FIELD(real_output)
      FIELD(real_out_tx_key)
      FIELD(real_out_output_secret_keys)
      FIELD(real_output_in_tx_index)
      FIELD(amount)
      FIELD(rct)
      FIELD(mask)

      if (real_output >= outputs.size())
        return false;
    END_SERIALIZE()
  };

  struct tx_destination_entry
  {
    std::string original;
    spend_view_public_keys addr;        //destination address
    uint64_t amount = 0;                    //money
    bool is_subaddress = false;

    tx_destination_entry() : addr(AUTO_VAL_INIT(addr)) { }

    tx_destination_entry
    (
     uint64_t amount
     , const spend_view_public_keys &ad
     , bool is_subaddress
     )
      :
        addr(ad)
      , amount(amount)
      , is_subaddress(is_subaddress)
    {}


    std::string address(network_type nettype) const
    {
      if (!original.empty())
      {
        return original;
      }

      return get_account_address_as_str(nettype, is_subaddress, addr);
    }

    BEGIN_SERIALIZE_OBJECT()
      FIELD(original)
      VARINT_FIELD(amount)
      FIELD(addr)
      FIELD(is_subaddress)
    END_SERIALIZE()
  };

  //---------------------------------------------------------------
  std::optional<
    std::tuple
    <
      transaction
      , std::vector<size_t>
      >
    > construct_tx_with_tx_key
    (
     const account_keys sender_account_keys
     , const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses
     , const std::vector<tx_source_entry> sources_in
     , const std::span<const tx_destination_entry> destinations
     , const std::vector<uint8_t> extra
     , const uint64_t unlock_time
     , const std::span<const crypto::secret_key> output_secret_keys
     );

  std::optional<block> generate_genesis_block
  (
   const std::string_view genesis_tx
   , const uint64_t nonce
   );

  std::optional<transaction> construct_miner_tx
  (
   const size_t height
   , const size_t current_block_weight
   , const uint64_t fee
   , const spend_view_public_keys miner_address
   );


}
