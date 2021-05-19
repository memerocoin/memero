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

#include "math/ringct/rctTypes.hpp"
#include "tools/serialization/serialization.h"
#include "cryptonote/tx/cryptonote_tx_utils.h" // keypair

namespace wallet {
namespace logic {
namespace type {
namespace transfer {

  struct transfer_details
  {
    uint64_t m_block_height;
    cryptonote::transaction_prefix m_tx;
    crypto::hash m_txid;
    size_t m_internal_output_index;
    uint64_t m_global_output_index;
    bool m_spent;
    bool m_frozen;
    uint64_t m_spent_height;
    crypto::key_image m_key_image; //TODO: key_image stored twice :(
    rct::key m_mask;
    uint64_t m_amount;
    bool m_rct;
    bool m_key_image_known;
    bool m_key_image_request; // view wallets: we want to request it; cold wallets: it was requested
    size_t m_pk_index;
    cryptonote::subaddress_index m_subaddr_index;
    bool m_key_image_partial;
    std::vector<rct::key> m_multisig_k;
    std::vector<rct::key> m_fake_multisig_info; // one per other participant
    std::vector<std::pair<uint64_t, crypto::hash>> m_uses;

    bool is_rct() const { return m_rct; }
    uint64_t amount() const { return m_amount; }
    const crypto::public_key &get_public_key() const
    {
      return boost::get<const cryptonote::txout_to_key>
        (m_tx.vout[m_internal_output_index].target).key;
    }

    BEGIN_SERIALIZE_OBJECT()
      FIELD(m_block_height)
      FIELD(m_tx)
      FIELD(m_txid)
      FIELD(m_internal_output_index)
      FIELD(m_global_output_index)
      FIELD(m_spent)
      FIELD(m_frozen)
      FIELD(m_spent_height)
      FIELD(m_key_image)
      FIELD(m_mask)
      FIELD(m_amount)
      FIELD(m_rct)
      FIELD(m_key_image_known)
      FIELD(m_key_image_request)
      FIELD(m_pk_index)
      FIELD(m_subaddr_index)
      FIELD(m_key_image_partial)
      FIELD(m_multisig_k)
      FIELD(m_fake_multisig_info)
      FIELD(m_uses)
    END_SERIALIZE()
  };

  struct unconfirmed_transfer_details
  {
    cryptonote::transaction_prefix m_tx;
    uint64_t m_amount_in;
    uint64_t m_amount_out;
    uint64_t m_change;
    time_t m_sent_time;
    std::vector<cryptonote::tx_destination_entry> m_dests;
    crypto::hash d_payment_id;
    enum { pending, pending_not_in_pool, failed } m_state;
    uint64_t m_timestamp;
    uint32_t m_subaddr_account;   // subaddress account of your wallet to be used in this transfer
    std::set<uint32_t> m_subaddr_indices;  // set of address indices used as inputs in this transfer
    std::vector<std::pair<crypto::key_image, std::vector<uint64_t>>> m_rings; // relative

    BEGIN_SERIALIZE_OBJECT()
      VERSION_FIELD(1)
      FIELD(m_tx)
      VARINT_FIELD(m_amount_in)
      VARINT_FIELD(m_amount_out)
      VARINT_FIELD(m_change)
      VARINT_FIELD(m_sent_time)
      FIELD(m_dests)
      FIELD(d_payment_id)
      if (version >= 1)
        VARINT_FIELD(m_state)
      VARINT_FIELD(m_timestamp)
      VARINT_FIELD(m_subaddr_account)
      FIELD(m_subaddr_indices)
      FIELD(m_rings)
    END_SERIALIZE()
  };

  struct confirmed_transfer_details
  {
    uint64_t m_amount_in;
    uint64_t m_amount_out;
    uint64_t m_change;
    uint64_t m_block_height;
    std::vector<cryptonote::tx_destination_entry> m_dests;
    crypto::hash d_payment_id;
    uint64_t m_timestamp;
    uint64_t m_unlock_time;
    uint32_t m_subaddr_account;   // subaddress account of your wallet to be used in this transfer
    std::set<uint32_t> m_subaddr_indices;  // set of address indices used as inputs in this transfer
    std::vector<std::pair<crypto::key_image, std::vector<uint64_t>>> m_rings; // relative

    confirmed_transfer_details(): m_amount_in(0), m_amount_out(0), m_change((uint64_t)-1), m_block_height(0), d_payment_id(crypto::null_hash), m_timestamp(0), m_unlock_time(0), m_subaddr_account((uint32_t)-1) {}
    confirmed_transfer_details(const unconfirmed_transfer_details &utd, uint64_t height):
      m_amount_in(utd.m_amount_in), m_amount_out(utd.m_amount_out), m_change(utd.m_change), m_block_height(height), m_dests(utd.m_dests), d_payment_id(crypto::null_hash), m_timestamp(utd.m_timestamp), m_unlock_time(utd.m_tx.unlock_time), m_subaddr_account(utd.m_subaddr_account), m_subaddr_indices(utd.m_subaddr_indices), m_rings(utd.m_rings) {}

    BEGIN_SERIALIZE_OBJECT()
      VERSION_FIELD(0)
      VARINT_FIELD(m_amount_in)
      VARINT_FIELD(m_amount_out)
      VARINT_FIELD(m_change)
      VARINT_FIELD(m_block_height)
      FIELD(m_dests)
      FIELD(d_payment_id)
      VARINT_FIELD(m_timestamp)
      VARINT_FIELD(m_unlock_time)
      VARINT_FIELD(m_subaddr_account)
      FIELD(m_subaddr_indices)
      FIELD(m_rings)
    END_SERIALIZE()
  };

} // transfer
} // type
} // logic
} // wallet
