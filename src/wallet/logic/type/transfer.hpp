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
    std::vector<wallet::logic::type::multisig::multisig_info> m_multisig_info; // one per other participant
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
      FIELD(m_multisig_info)
      FIELD(m_uses)
    END_SERIALIZE()
  };


} // transfer
} // type
} // logic
} // wallet

using namespace wallet::logic::type::transfer;

BOOST_CLASS_VERSION(transfer_details, 12)

namespace boost
{
  namespace serialization
  {
    using namespace wallet::logic::type::transfer;

    template <class Archive>
    inline typename std::enable_if<!Archive::is_loading::value, void>::type initialize_transfer_details(Archive &a, transfer_details &x, const boost::serialization::version_type ver)
    {
    }
    template <class Archive>
    inline typename std::enable_if<Archive::is_loading::value, void>::type initialize_transfer_details(Archive &a, transfer_details &x, const boost::serialization::version_type ver)
    {
    }

    template <class Archive>
    inline void serialize(Archive &a, transfer_details &x, const boost::serialization::version_type ver)
    {
      a & x.m_block_height;
      a & x.m_global_output_index;
      a & x.m_internal_output_index;
      a & x.m_tx;
      a & x.m_spent;
      a & x.m_key_image;
      a & x.m_mask;
      a & x.m_amount;
      a & x.m_spent_height;
      a & x.m_txid;
      a & x.m_rct;
      a & x.m_key_image_known;
      a & x.m_pk_index;
      a & x.m_subaddr_index;
      a & x.m_multisig_info;
      a & x.m_multisig_k;
      a & x.m_key_image_partial;
      a & x.m_key_image_request;
      a & x.m_uses;
      a & x.m_frozen;
    }

  }
}
