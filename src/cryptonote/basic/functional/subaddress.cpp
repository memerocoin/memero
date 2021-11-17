/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/



#include "subaddress.hpp"

#include "cryptonote/tx/pseudo_functional/tx_utils.hpp"

#include "tools/epee/include/int-util.h"
#include "tools/epee/include/string_tools.h"

#include "math/crypto/controller/keyGen.hpp"


namespace cryptonote {

  crypto::secret_key get_subaddress_spend_secret_key
  (
   const cryptonote::spend_view_secret_keys keys
   , const cryptonote::subaddress_index index
   )
  {
    if (index.is_zero())
      return keys.m_spend_secret_key;

    const auto offset = hash_secret_key_with_subaddress_index(keys.m_view_secret_key, index);

    return crypto::s2sk(keys.m_spend_secret_key + offset);
  }

  crypto::secret_key get_subaddress_view_secret_key_base_G
  (
   const cryptonote::spend_view_secret_keys keys
   , const cryptonote::subaddress_index index
   )
  {
    return index.is_zero()
      ? keys.m_view_secret_key
      : s2sk(keys.m_view_secret_key * get_subaddress_spend_secret_key(keys, index));
  }

  crypto::public_key get_subaddress_spend_public_key
  (
   const cryptonote::spend_view_secret_keys keys
   , const cryptonote::subaddress_index index
   )
  {
    return crypto::to_pk(get_subaddress_spend_secret_key(keys, index));
  }

  crypto::public_key get_subaddress_view_public_key
  (
   const cryptonote::spend_view_secret_keys keys
   , const cryptonote::subaddress_index index
   )
  {
    return crypto::to_pk(get_subaddress_view_secret_key_base_G(keys, index));
  }


  std::vector<crypto::public_key> get_subaddress_spend_public_keys
  (
    const cryptonote::spend_view_secret_keys keys
    , const uint32_t account
    , const uint32_t begin
    , const uint32_t end
    )
  {
    LOG_ERROR_AND_THROW_UNLESS(begin <= end, "begin > end");

    std::vector<crypto::public_key> pkeys;

    for (uint32_t idx = begin; idx < end; ++idx)
    {
      pkeys.push_back(get_subaddress_spend_public_key(keys, {account, idx}));
    }
    return pkeys;
  }


  cryptonote::spend_view_public_keys get_subaddress
  (
   const cryptonote::spend_view_secret_keys keys
   , const cryptonote::subaddress_index index
   )
  {
    return
      {
        cryptonote::get_subaddress_spend_public_key(keys, index)
        , cryptonote::get_subaddress_view_public_key(keys, index)
      };
  }

  crypto::ec_scalar hash_secret_key_with_subaddress_index
  (
   const crypto::secret_key sec
   , const cryptonote::subaddress_index index
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

}
