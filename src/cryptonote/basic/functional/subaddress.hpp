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

#pragma once

#include "cryptonote/basic/type/subaddress_index.hpp"

#include "math/crypto/functional/key.hpp"

#include "tools/epee/include/serialization/keyvalue_serialization.h" // eepe named serialization

namespace cryptonote {

  struct spend_view_secret_keys
  {
    crypto::secret_key   m_spend_secret_key;
    crypto::secret_key   m_view_secret_key;
  };

  struct spend_view_public_keys_unsafe
  {
    crypto::ec_point_unsafe m_spend_public_key_unsafe;
    crypto::ec_point_unsafe m_view_public_key_unsafe;

    BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_spend_public_key_unsafe)
    KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_view_public_key_unsafe)
    END_KV_SERIALIZE_MAP()
  };

  struct spend_view_public_keys
  {
    crypto::public_key m_spend_public_key;
    crypto::public_key m_view_public_key;

    bool operator==(const spend_view_public_keys& rhs) const = default;

    BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_spend_public_key)
    KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_view_public_key)
    END_KV_SERIALIZE_MAP()
  };

  crypto::secret_key get_subaddress_spend_secret_key
  (
   const cryptonote::spend_view_secret_keys keys
   , const cryptonote::subaddress_index index
   );

  crypto::secret_key get_subaddress_view_secret_key_base_G
  (
   const cryptonote::spend_view_secret_keys keys
   , const cryptonote::subaddress_index index
   );

  crypto::public_key get_subaddress_spend_public_key
  (
   const cryptonote::spend_view_secret_keys keys
   , const cryptonote::subaddress_index index
   );

  crypto::public_key get_subaddress_view_public_key
  (
   const cryptonote::spend_view_secret_keys keys
   , const cryptonote::subaddress_index index
   );

  std::vector<crypto::public_key> get_subaddress_spend_public_keys
  (
   const cryptonote::spend_view_secret_keys keys
   , const uint32_t account
   , const uint32_t begin
   , const uint32_t end
   );

  cryptonote::spend_view_public_keys get_subaddress
  (
   const cryptonote::spend_view_secret_keys keys
   , const cryptonote::subaddress_index index
   );

  crypto::ec_scalar hash_secret_key_with_subaddress_index
  (
   const crypto::secret_key sec
   , const cryptonote::subaddress_index index
   );

}
