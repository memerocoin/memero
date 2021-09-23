// Copyright (c) 2017-2020, The Monero Project
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




#include "subaddress.hpp"

#include "cryptonote/tx/pseudo_functional/tx_utils.hpp"

#include "tools/epee/include/int-util.h"
#include "tools/epee/include/string_tools.h"

#include "math/ringct/controller/rctGen.hpp"
#include "math/crypto/controller/keyGen.hpp"


namespace cryptonote {
  /* ======================================================================= */
  /*                             WALLET & ADDRESS                            */
  /* ======================================================================= */


  /* ======================================================================= */
  /*                               SUB ADDRESS                               */
  /* ======================================================================= */

  crypto::secret_key get_subaddress_spend_secret_key
  (
   const cryptonote::account_keys& keys
   , const cryptonote::subaddress_index &index
   )
  {
    if (index.is_zero())
      return keys.m_spend_secret_key_base;

    const auto offset = hash_secret_key_with_subaddress_index(keys.m_view_secret_key, index);

    return crypto::s2sk(keys.m_spend_secret_key_base + offset);
  }

  crypto::public_key get_subaddress_spend_public_key
  (
   const cryptonote::account_keys& keys
   , const cryptonote::subaddress_index &index
   )
  {
    if (index.is_zero())
      return keys.m_account_address.m_spend_public_key;

    // m = Hs(a || index_major || index_minor)
    const auto offset = hash_secret_key_with_subaddress_index(keys.m_view_secret_key, index);

    // D = B + M
    return crypto::p2pk(keys.m_account_address.m_spend_public_key + crypto::multBase(offset));
  }


  std::vector<crypto::public_key> get_subaddress_spend_public_keys
  (
    const cryptonote::account_keys &keys
    , const uint32_t account
    , const uint32_t begin
    , const uint32_t end
    )
  {
    LOG_ERROR_AND_THROW_UNLESS(begin <= end, "begin > end");

    std::vector<crypto::public_key> pkeys;
    pkeys.reserve(end - begin);
    cryptonote::subaddress_index index = {account, begin};

    const auto public_spend_key = keys.m_account_address.m_spend_public_key;
    if (!is_safe_point(public_spend_key)) {
      LOG_FATAL("public spend key is not on the main group");
    }


    for (uint32_t idx = begin; idx < end; ++idx)
    {
      index.minor = idx;
      if (index.is_zero())
      {
          pkeys.push_back(keys.m_account_address.m_spend_public_key);
          continue;
      }
      pkeys.push_back(get_subaddress_spend_public_key(keys, index));
    }
    return pkeys;
  }

  cryptonote::account_public_address get_subaddress
  (
   const cryptonote::account_keys& keys
   , const cryptonote::subaddress_index &index
   )
  {
    if (index.is_zero())
      return keys.m_account_address;

    crypto::public_key D = ::cryptonote::get_subaddress_spend_public_key(keys, index);

    // C = a*D
    crypto::public_key C = rct::rct_p2pk
      (rct::multP(rct::pk2rct_p(D), rct::sk2rct_s(keys.m_view_secret_key)));

    // result: (C, D)
    cryptonote::account_public_address address;
    address.m_view_public_key  = C;
    address.m_spend_public_key = D;
    return address;
  }

  crypto::ec_scalar hash_secret_key_with_subaddress_index
  (
   const crypto::secret_key &sec
   , const cryptonote::subaddress_index &index
   )
  {
    const uint32_t major_i = SWAP32LE(index.major);
    const uint32_t minor_i = SWAP32LE(index.minor);
    const epee::blob::data major = epee::blob::data((uint8_t*)&major_i, sizeof(uint32_t));
    const epee::blob::data minor = epee::blob::data((uint8_t*)&minor_i, sizeof(uint32_t));


    // here trailing 0 is part of the HASH_KEY ..
    const epee::blob::data hashData =
      epee::string_tools::string_to_blob(config::HASH_KEY_SUBADDRESS)
      + epee::blob::data({0})
      + epee::blob::data(sec.data.begin(), sec.data.size())
      + major
      + minor;

    return crypto::hash_to_scalar(hashData);
  }

  /* ======================================================================= */
  /*                            DERIVATION & KEY                             */
  /* ======================================================================= */

}
