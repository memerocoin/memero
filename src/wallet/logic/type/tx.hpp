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

#include <utility>
#include <cstdint>

#include "ringct/rctTypes.h"
#include "serialization/serialization.h"
#include "cryptonote/core/cryptonote_tx_utils.h" // keypair

#include "wallet/logic/type/multisig.hpp" // multisig_info

namespace wallet {
namespace logic {
namespace type {
namespace tx {

  struct tx_scan_info_t
  {
    cryptonote::keypair in_ephemeral;
    crypto::key_image ki;
    rct::key mask;
    uint64_t amount;
    uint64_t money_transfered;
    bool error;
    std::optional<cryptonote::subaddress_receive_info> received;

    tx_scan_info_t(): amount(0), money_transfered(0), error(true) {}
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
    rct::RCTConfig rct_config;
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
      FIELD(rct_config)
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
    std::string key_images;
    crypto::secret_key tx_key;
    std::vector<crypto::secret_key> additional_tx_keys;
    std::vector<cryptonote::tx_destination_entry> dests;
    std::vector<wallet::logic::type::multisig::multisig_sig> multisig_sigs;

    tx_construction_data construction_data;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(tx)
      FIELD(dust)
      FIELD(fee)
      FIELD(dust_added_to_fee)
      FIELD(change_dts)
      FIELD(selected_transfers)
      FIELD(key_images)
      FIELD(tx_key)
      FIELD(additional_tx_keys)
      FIELD(dests)
      FIELD(construction_data)
      FIELD(multisig_sigs)
    END_SERIALIZE()
  };

} // tx
} // type
} // logic
} // wallet


using namespace wallet::logic::type::tx;

BOOST_CLASS_VERSION(tx_construction_data, 4)
BOOST_CLASS_VERSION(pending_tx, 3)


namespace boost
{
  namespace serialization
  {
    using namespace wallet::logic::type::tx;

    template <class Archive>
    inline void serialize(Archive &a, tx_construction_data &x, const boost::serialization::version_type ver)
    {
      a & x.sources;
      a & x.change_dts;
      a & x.splitted_dsts;
      if (ver < 2)
      {
        // load list to vector
        std::list<size_t> selected_transfers;
        a & selected_transfers;
        x.selected_transfers.clear();
        x.selected_transfers.reserve(selected_transfers.size());
        for (size_t t: selected_transfers)
          x.selected_transfers.push_back(t);
      }
      a & x.extra;
      a & x.unlock_time;
      a & x.use_rct;
      a & x.dests;
      if (ver < 1)
      {
        x.subaddr_account = 0;
        return;
      }
      a & x.subaddr_account;
      a & x.subaddr_indices;
      if (ver < 2)
      {
        if (!typename Archive::is_saving())
          x.rct_config = { rct::RangeProofBorromean, 0 };
        return;
      }
      a & x.selected_transfers;
      if (ver < 3)
      {
        if (!typename Archive::is_saving())
          x.rct_config = { rct::RangeProofBorromean, 0 };
        return;
      }
      if (ver < 4)
      {
        bool use_bulletproofs = x.rct_config.range_proof_type != rct::RangeProofBorromean;
        a & use_bulletproofs;
        if (!typename Archive::is_saving())
          x.rct_config = { use_bulletproofs ? rct::RangeProofBulletproof : rct::RangeProofBorromean, 0 };
        return;
      }
      a & x.rct_config;
    }

    template <class Archive>
    inline void serialize(Archive &a, pending_tx &x, const boost::serialization::version_type ver)
    {
      a & x.tx;
      a & x.dust;
      a & x.fee;
      a & x.dust_added_to_fee;
      a & x.change_dts;
      if (ver < 2)
        {
          // load list to vector
          std::list<size_t> selected_transfers;
          a & selected_transfers;
          x.selected_transfers.clear();
          x.selected_transfers.reserve(selected_transfers.size());
          for (size_t t: selected_transfers)
            x.selected_transfers.push_back(t);
        }
      a & x.key_images;
      a & x.tx_key;
      a & x.dests;
      a & x.construction_data;
      if (ver < 1)
        return;
      a & x.additional_tx_keys;
      if (ver < 2)
        return;
      a & x.selected_transfers;
      if (ver < 3)
        return;
      a & x.multisig_sigs;
    }
  }
}
