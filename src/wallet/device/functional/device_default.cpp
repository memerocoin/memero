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




#include "device_default.hpp"

#include "cryptonote/tx/cryptonote_tx_utils.h"

#include "tools/epee/include/int-util.h"
#include "tools/epee/include/string_tools.h"

#include "math/ringct/controller/rctGen.hpp"
#include "math/crypto/controller/keyGen.hpp"


namespace device {
  /* ======================================================================= */
  /*                             WALLET & ADDRESS                            */
  /* ======================================================================= */

  crypto::chacha_key generate_chacha_key(const cryptonote::account_keys &keys, const uint64_t kdf_rounds) {
    crypto::chacha_key key;
    const crypto::secret_key &view_key = keys.m_view_secret_key;
    const crypto::secret_key &spend_key = keys.m_spend_secret_key;
    std::array<char, sizeof(view_key) + sizeof(spend_key) + 1> data;
    memcpy(data.data(), &view_key, sizeof(view_key));
    memcpy(data.data() + sizeof(view_key), &spend_key, sizeof(spend_key));
    data[sizeof(data) - 1] = config::HASH_KEY_WALLET;
    crypto::generate_chacha_key(data.data(), sizeof(data), key, kdf_rounds);
    return key;
  }


  /* ======================================================================= */
  /*                               SUB ADDRESS                               */
  /* ======================================================================= */

  crypto::public_key get_subaddress_spend_public_key
  (
   const cryptonote::account_keys& keys
   , const cryptonote::subaddress_index &index
   )
  {
    if (index.is_zero())
      return keys.m_account_address.m_spend_public_key;

    // m = Hs(a || index_major || index_minor)
    const crypto::secret_key m = get_subaddress_secret_key(keys.m_view_secret_key, index);

    // M = m*G
    const crypto::public_key M = crypto::p2pk(crypto::multBase(m));

    // D = B + M
    return crypto::p2pk(keys.m_account_address.m_spend_public_key + M);
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
    if (!is_valid_point(public_spend_key)) {
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
      crypto::secret_key m = get_subaddress_secret_key(keys.m_view_secret_key, index);

      // M = m*G
      const crypto::ec_point mG = crypto::multBase(m);

      // D = B + M
      const crypto::public_key D = crypto::p2pk(public_spend_key + mG);

      pkeys.push_back(D);
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

    crypto::public_key D = ::device::get_subaddress_spend_public_key(keys, index);

    // C = a*D
    crypto::public_key C = rct::rct_p2pk
      (rct::multP(rct::pk2rct_p(D), rct::sk2rct_s(keys.m_view_secret_key)));

    // result: (C, D)
    cryptonote::account_public_address address;
    address.m_view_public_key  = C;
    address.m_spend_public_key = D;
    return address;
  }

  crypto::secret_key get_subaddress_secret_key
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

    return s2sk(crypto::hash_to_scalar(hashData));
  }

  /* ======================================================================= */
  /*                            DERIVATION & KEY                             */
  /* ======================================================================= */

  bool verify_keys(const crypto::secret_key &secret_key, const crypto::public_key &public_key) {
    const auto calculated_pub = crypto::to_maybe_pk(secret_key);
    return public_key == calculated_pub;
  }

}
