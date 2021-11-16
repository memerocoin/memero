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

#include "wallet/api/wallet_errors.h"

#include "cryptonote/basic/functional/subaddress.hpp"

#include "tools/common/base58.h"

#include "math/crypto/controller/keyGen.hpp"



namespace wallet {
namespace logic {
namespace functional {
namespace signature {

  // Set up an address signature message hash
  // Hash data: domain separator, spend public key, view public key, mode identifier, payload data
  crypto::hash get_message_hash
  (
   const std::string &data
   )
  {
    const std::string message = std::string(config::MESSAGE_SIGNING_HEADER) + data;
    return crypto::sha3(epee::string_tools::string_to_blob(message));
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
    crypto::schnorr_signature_unnormalized sig_unsafe{};
    if (sizeof(sig_unsafe) != decoded.size()) {
      LOG_PRINT_L0("Signature decoding error");
      return {};
    }

    memcpy(&sig_unsafe, decoded.data(), decoded.size());

    const auto sig = maybe_valid_schnorr_signature(sig_unsafe);

    if (!sig) return {};



    // Test each mode and return which mode, if either, succeeded
    const crypto::hash hash = get_message_hash(data);
    constexpr unsigned ver = config::MESSAGE_SIGNING_VERSION;
    if (crypto::verify_schnorr_signature(hash.blob(), address.m_spend_public_key, *sig))
      return {true, ver, wallet::logic::type::message_signature::sign_with_spend_key };

    if (crypto::verify_schnorr_signature(hash.blob(), address.m_view_public_key, *sig, address.m_spend_public_key))
      return {true, ver, wallet::logic::type::message_signature::sign_with_view_key };

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
   )
  {
    const crypto::hash hash = get_message_hash(data);

    const crypto::secret_key skey
      = signature_type == wallet::logic::type::message_signature::sign_with_spend_key
      ? cryptonote::get_subaddress_spend_secret_key(keys.get_spend_view_secret_keys(), index)
      : keys.m_view_secret_key
      ;

    LOG_ERROR_AND_THROW_UNLESS(crypto::is_reduced(skey), "Invalid signing key");

    const std::optional<crypto::ec_point> base 
      = signature_type == wallet::logic::type::message_signature::sign_with_spend_key
      ? std::nullopt
      : std::optional<crypto::ec_point>
      {
        cryptonote::get_subaddress_spend_public_key(keys.get_spend_view_secret_keys(), index)
      }
      ;

    const crypto::schnorr_signature signature = crypto::generate_schnorr_signature(hash.blob(), skey, base);
    return std::string(config::MESSAGE_SIGNING_HEADER) +
      tools::base58::encode(epee::string_tools::blob_to_string(epee::pod_to_span(signature)));
  }

} // signature
} // functional
} // logic
} // wallet
