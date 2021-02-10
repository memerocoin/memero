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

namespace wallet {
namespace logic {
namespace type {
namespace payment {

  typedef std::vector<uint64_t> amounts_container;

  struct payment_details
  {
    crypto::hash m_tx_hash;
    uint64_t m_amount;
    amounts_container m_amounts;
    uint64_t m_fee;
    uint64_t m_block_height;
    uint64_t m_unlock_time;
    uint64_t m_timestamp;
    bool m_coinbase;
    cryptonote::subaddress_index m_subaddr_index;

    BEGIN_SERIALIZE_OBJECT()
      VERSION_FIELD(0)
      FIELD(m_tx_hash)
      VARINT_FIELD(m_amount)
      FIELD(m_amounts)
      VARINT_FIELD(m_fee)
      VARINT_FIELD(m_block_height)
      VARINT_FIELD(m_unlock_time)
      VARINT_FIELD(m_timestamp)
      FIELD(m_coinbase)
      FIELD(m_subaddr_index)
    END_SERIALIZE()
  };

  struct address_tx : payment_details
  {
    bool m_mempool;
    bool m_incoming;
  };

  struct pool_payment_details
  {
    payment_details m_pd;
    bool m_double_spend_seen;

    BEGIN_SERIALIZE_OBJECT()
      VERSION_FIELD(0)
      FIELD(m_pd)
      FIELD(m_double_spend_seen)
    END_SERIALIZE()
  };

} // payment
} // type
} // logic
} // wallet


using namespace wallet::logic::type::payment;

BOOST_CLASS_VERSION(payment_details, 5)
BOOST_CLASS_VERSION(pool_payment_details, 1)

namespace boost
{
  namespace serialization
  {
    using namespace wallet::logic::type::payment;

    template <class Archive>
    inline void serialize(Archive& a, payment_details& x, const boost::serialization::version_type ver)
    {
      a & x.m_tx_hash;
      a & x.m_amount;
      a & x.m_block_height;
      a & x.m_unlock_time;
      a & x.m_timestamp;
      a & x.m_subaddr_index;
      a & x.m_fee;
      a & x.m_coinbase;
      a & x.m_amounts;
    }

    template <class Archive>
    inline void serialize(Archive& a, pool_payment_details& x, const boost::serialization::version_type ver)
    {
      a & x.m_pd;
      a & x.m_double_spend_seen;
    }

  }
}
