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

#include <vector>

#include "ringct/rctTypes.h"
#include "serialization/serialization.h"

namespace wallet {
namespace logic {
namespace type {
namespace multisig {

  struct multisig_info
  {
    struct LR
    {
      rct::key m_L;
      rct::key m_R;

      BEGIN_SERIALIZE_OBJECT()
      FIELD(m_L)
      FIELD(m_R)
      END_SERIALIZE()
    };

    crypto::public_key m_signer;
    std::vector<LR> m_LR;
    std::vector<crypto::key_image> m_partial_key_images; // one per key the participant has

    BEGIN_SERIALIZE_OBJECT()
    FIELD(m_signer)
    FIELD(m_LR)
    FIELD(m_partial_key_images)
    END_SERIALIZE()
  };

  struct multisig_sig
  {
    rct::rctSig sigs;
    std::unordered_set<crypto::public_key> ignore;
    std::unordered_set<rct::key> used_L;
    std::unordered_set<crypto::public_key> signing_keys;
    rct::multisig_out msout;

    BEGIN_SERIALIZE_OBJECT()
    VERSION_FIELD(0)
    FIELD(sigs)
    FIELD(ignore)
    FIELD(used_L)
    FIELD(signing_keys)
    FIELD(msout)
    END_SERIALIZE()
  };

}
} // type
} // logic
} // wallet


using namespace wallet::logic::type::multisig;

BOOST_CLASS_VERSION(multisig_info, 1)
BOOST_CLASS_VERSION(multisig_info::LR, 0)
BOOST_CLASS_VERSION(multisig_sig, 0)


namespace boost
{
  namespace serialization
  {
    using namespace wallet::logic::type::multisig;

    template <class Archive>
    inline void serialize(Archive &a, multisig_info::LR &x, const boost::serialization::version_type ver)
    {
      a & x.m_L;
      a & x.m_R;
    }

    template <class Archive>
    inline void serialize(Archive &a, multisig_info &x, const boost::serialization::version_type ver)
    {
      a & x.m_signer;
      a & x.m_LR;
      a & x.m_partial_key_images;
    }

    template <class Archive>
    inline void serialize(Archive &a, multisig_sig &x, const boost::serialization::version_type ver)
    {
      a & x.sigs;
      a & x.ignore;
      a & x.used_L;
      a & x.signing_keys;
      a & x.msout;
    }

  }
}
