// Copyright (c) 2021, The Lolnero Project
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

#include "cryptonote/basic/functional/format_utils.hpp"

namespace wallet {
namespace logic {
namespace type {
namespace tx {

  struct tx_scan_info_t
  {
    cryptonote::keypair output_spend_key;
    crypto::key_image ki;
    rct::rct_scalar mask;
    uint64_t amount;
    uint64_t money_transfered;
    bool error;
    std::optional<cryptonote::subaddress_receive_info> received;

    tx_scan_info_t(): amount(0), money_transfered(0), error(true) {}

    tx_scan_info_t
    (
     uint64_t money_transfered
     , std::optional<cryptonote::subaddress_receive_info> received
     )
      : amount(0), money_transfered(money_transfered), error(false), received(received) {}
  };

  struct tx_construction_data
  {
    std::vector<cryptonote::tx_source_entry> sources;
    cryptonote::tx_destination_entry change_dts;
    std::vector<cryptonote::tx_destination_entry> splitted_dsts; // split, includes change
    std::vector<size_t> selected_transfers;
    std::vector<uint8_t> extra;
    uint64_t unlock_time;
    bool use_rct;
    std::vector<cryptonote::tx_destination_entry> dests; // original setup, does not include change
    uint32_t subaddr_account;   // subaddress account of your wallet to be used in this transfer
    std::set<uint32_t> subaddr_indices;  // set of address indices used as inputs in this transfer

    BEGIN_SERIALIZE_OBJECT()
      FIELD(sources)
      FIELD(change_dts)
      FIELD(splitted_dsts)
      FIELD(selected_transfers)
      FIELD(extra)
      FIELD(unlock_time)
      FIELD(use_rct)
      FIELD(dests)
      FIELD(subaddr_account)
      FIELD(subaddr_indices)
    END_SERIALIZE()
  };

  // The convention for destinations is:
  // dests does not include change
  // splitted_dsts (in construction_data) does
  struct pending_tx
  {
    cryptonote::transaction tx;
    uint64_t dust, fee;
    bool dust_added_to_fee;
    cryptonote::tx_destination_entry change_dts;
    std::vector<size_t> selected_transfers;
    std::string output_spend_key_images;
    std::vector<crypto::secret_key> output_secret_keys;
    std::vector<cryptonote::tx_destination_entry> dests;

    tx_construction_data construction_data;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(tx)
      FIELD(dust)
      FIELD(fee)
      FIELD(dust_added_to_fee)
      FIELD(change_dts)
      FIELD(selected_transfers)
      FIELD(output_spend_key_images)
      FIELD(output_secret_keys)
      FIELD(dests)
      FIELD(construction_data)
    END_SERIALIZE()
  };

} // tx
} // type
} // logic
} // wallet
