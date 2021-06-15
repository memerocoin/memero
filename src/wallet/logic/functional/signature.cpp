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


#include "signature.hpp"

#include <openssl/evp.h>

#include "tools/epee/include/misc_log_ex.h"
#include "tools/common/base58.h"

#include "wallet/api/wallet_errors.h"

#include "config/lol.hpp"

namespace wallet {
namespace logic {
namespace functional {
namespace signature {

  // Set up an address signature message hash
  // Hash data: domain separator, spend public key, view public key, mode identifier, payload data
  static crypto::hash get_message_hash
  (
   const std::string &data
   , const crypto::public_key &spend_key
   , const crypto::public_key &view_key
   , const uint8_t mode
   )
  {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(ctx, (const uint8_t*)config::HASH_KEY_MESSAGE_SIGNING.data(), config::HASH_KEY_MESSAGE_SIGNING.length()); // includes NUL
    EVP_DigestUpdate(ctx, (const uint8_t*)&spend_key, sizeof(crypto::public_key));
    EVP_DigestUpdate(ctx, (const uint8_t*)&view_key, sizeof(crypto::public_key));
    EVP_DigestUpdate(ctx, (const uint8_t*)&mode, sizeof(uint8_t));
    char len_buf[(sizeof(size_t) * 8 + 6) / 7];
    char *ptr = len_buf;
    tools::write_varint(ptr, data.size());
    CHECK_AND_ASSERT_THROW_MES(ptr > len_buf && ptr <= len_buf + sizeof(len_buf), "Length overflow");
    EVP_DigestUpdate(ctx, (const uint8_t*)len_buf, ptr - len_buf);
    EVP_DigestUpdate(ctx, (const uint8_t*)data.data(), data.size());
    crypto::hash hash;
    EVP_DigestFinal(ctx, (uint8_t*)&hash, NULL);
    EVP_MD_CTX_free(ctx);
    return hash;
  }

  wallet::logic::type::message_signature::message_signature_result_t verify
  (
   const std::string &data
   , const cryptonote::account_public_address &address
   , const std::string &signature
   )
  {
    constexpr size_t v2_header_len = config::MESSAGE_SIGNING_HEADER.length();
    const bool v2 = signature.size() >= v2_header_len
      && signature.substr(0, v2_header_len) == std::string(config::MESSAGE_SIGNING_HEADER);
    if (!v2)
    {
      LOG_PRINT_L0("Signature header check error");
      return {};
    }
    std::string decoded;
    if (!tools::base58::decode(signature.substr(v2_header_len), decoded)) {
      LOG_PRINT_L0("Signature decoding error");
      return {};
    }
    crypto::signature s;
    if (sizeof(s) != decoded.size()) {
      LOG_PRINT_L0("Signature decoding error");
      return {};
    }
    memcpy(&s, decoded.data(), sizeof(s));

    // Test each mode and return which mode, if either, succeeded
    const crypto::hash spend_key_hash =
      get_message_hash(data,address.m_spend_public_key,address.m_view_public_key,(uint8_t) 0);
    if (crypto::check_signature(spend_key_hash, address.m_spend_public_key, s))
      return {true, 2u, false, wallet::logic::type::message_signature::sign_with_spend_key };

    const crypto::hash view_key_hash =
      get_message_hash(data,address.m_spend_public_key,address.m_view_public_key,(uint8_t) 1);
    if (crypto::check_signature(view_key_hash, address.m_view_public_key, s))
      return {true, 2u, false, wallet::logic::type::message_signature::sign_with_view_key };

    // Both modes failed
    return {};
  }


  // Sign a message with a private key from either the base address or a subaddress
  // The signature is also bound to both keys and the signature mode (spend, view) to prevent unintended reuse
  const std::string sign
  (
   const std::string &data
   , const wallet::logic::type::message_signature::message_signature_type_t signature_type
   , const cryptonote::subaddress_index index
   , const cryptonote::account_keys &keys
   , const crypto::secret_key &subaddress_secret_view_key
   )
  {
    // const cryptonote::account_keys &keys = m_account.get_keys();
    crypto::signature signature;
    crypto::secret_key skey, m;
    crypto::secret_key skey_spend, skey_view;
    crypto::public_key pkey;
    crypto::public_key pkey_spend, pkey_view; // to include both in hash
    crypto::hash hash;
    uint8_t mode;

    // Use the base address
    if (index.is_zero())
    {
      switch (signature_type)
      {
        case wallet::logic::type::message_signature::sign_with_spend_key:
          skey = keys.m_spend_secret_key;
          pkey = keys.m_account_address.m_spend_public_key;
          mode = 0;
          break;
        case wallet::logic::type::message_signature::sign_with_view_key:
          skey = keys.m_view_secret_key;
          pkey = keys.m_account_address.m_view_public_key;
          mode = 1;
          break;
        default: CHECK_AND_ASSERT_THROW_MES(false, "Invalid signature type requested");
      }
      hash = get_message_hash(data,keys.m_account_address.m_spend_public_key,keys.m_account_address.m_view_public_key,mode);
    }
    // Use a subaddress
    else
    {
      skey_spend = keys.m_spend_secret_key;
      // m = m_account.get_device().get_subaddress_secret_key(keys.m_view_secret_key, index);
      m = subaddress_secret_view_key;
      sc_add((unsigned char*)&skey_spend, (unsigned char*)&m, (unsigned char*)&skey_spend);
      secret_key_to_public_key(skey_spend,pkey_spend);
      sc_mul((unsigned char*)&skey_view, (unsigned char*)&keys.m_view_secret_key, (unsigned char*)&skey_spend);
      secret_key_to_public_key(skey_view,pkey_view);
      switch (signature_type)
      {
        case wallet::logic::type::message_signature::sign_with_spend_key:
          skey = skey_spend;
          pkey = pkey_spend;
          mode = 0;
          break;
        case wallet::logic::type::message_signature::sign_with_view_key:
          skey = skey_view;
          pkey = pkey_view;
          mode = 1;
          break;
        default: CHECK_AND_ASSERT_THROW_MES(false, "Invalid signature type requested");
      }
      secret_key_to_public_key(skey, pkey);
      hash = get_message_hash(data,pkey_spend,pkey_view,mode);
    }
    crypto::generate_signature(hash, pkey, skey, signature);
    return std::string(config::MESSAGE_SIGNING_HEADER) + tools::base58::encode(std::string((const char *)&signature, sizeof(signature)));
  }

} // signature
} // functional
} // logic
} // wallet
