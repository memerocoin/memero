/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "key.hpp"

#include "tools/common/varint.h"
#include "tools/epee/include/string_tools.h"
#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/int-util.h"

#include "config/cryptonote.hpp"

#include <sodium.h>

#include <cassert>
#include <mutex>
#include <memory>

namespace crypto {

  public_key to_pk(const secret_key& sk) noexcept {
    return p2pk(multBase(sk));
  }


  ec_scalar hash_to_scalar(const std::span<const uint8_t> x) noexcept {
    const auto h = sha3(x);
    return reduce(h2s(h));
  }


  // sender holds the private key of the tx output public key
  bool verify_tx_output_signatures
  (
   const hash message_hash
   , const public_key tx_output_public_key
   , const std::optional<public_key> view_key_base // spend public key
   , const schnorr_signature sig
   ) noexcept
  {
    const auto hash_key = epee::string_tools::string_to_blob(config::HASH_KEY_TX_OUTPUT_SIGNATURES_V1);
    return verify_schnorr_signature(hash_key + message_hash.blob(), tx_output_public_key, sig, view_key_base);
  }

  ec_point hash_to_point_via_field(const crypto::crypto_data k) {
    return viaFieldMult8(h2p(sha3(k.data)));
  }

  key_image derive_public_key_image(const secret_key sec) noexcept {
    return p2img(hash_to_point_via_field(to_pk(sec)) ^ sec);
  }

  ecdh_shared_secret derive_tx_output_ecdh_shared_secret
  (
   const public_key pk
   , const secret_key sk
   ) noexcept
  {
    return p2ecdh_shared_secret(mult8(pk) ^ sk);
  }

  ec_scalar hash_tx_output_shared_secret_to_scalar
  (
   const ecdh_shared_secret &tx_output_shared_secret
   , const size_t index
   ) noexcept
  {
    const epee::blob::data hashData =
      tx_output_shared_secret.blob()
      + epee::string_tools::string_to_blob(tools::get_varint_data(index));

    return hash_to_scalar(hashData);
  }

  secret_key compute_output_spend_sk_from_subaddress_spend_sk
  (
   const ecdh_shared_secret &tx_output_shared_secret
   , const size_t output_index
   , const secret_key &spend_sk
   ) noexcept
  {
    const ec_scalar shared_secret_hash = hash_tx_output_shared_secret_to_scalar(tx_output_shared_secret, output_index);
    return s2sk(spend_sk + shared_secret_hash);
  }

  std::optional<public_key> compute_output_spend_pk_from_subaddress_spend_pk
  (
   const ecdh_shared_secret &tx_output_shared_secret
   , const size_t output_index
   , const ec_point_unsafe &unsafe_spend_public_key
   ) noexcept
  {
    const auto spend_public_key = maybeSafePoint(unsafe_spend_public_key);
    if (!spend_public_key) return {};

    const ec_scalar shared_secret_hash = hash_tx_output_shared_secret_to_scalar(tx_output_shared_secret, output_index);
    return p2pk(multBase(shared_secret_hash) + *spend_public_key);
  }

  std::optional<public_key> compute_subaddress_spend_pk_from_output_spend_pk
  (
     const ecdh_shared_secret tx_output_shared_secret
   , const std::size_t output_index
   , const ec_point output_spend_pk
   ) noexcept
  {
    const ec_scalar shared_secret_hash = hash_tx_output_shared_secret_to_scalar(tx_output_shared_secret, output_index);

    if (shared_secret_hash == s_0) return {};

    return p2pk(output_spend_pk - multBase(shared_secret_hash));
  }

  std::optional<crypto::public_key> maybeNotNull(const crypto::public_key x) {
    if (x == crypto::null_pkey) {
      return {};
    } else {
      return x;
    }
  }

  bool verify_keys(const crypto::ec_scalar_unnormalized secret_key, const crypto::public_key public_key) {
    if (is_not_reduced(secret_key)) return false;
    return public_key == crypto::to_pk(crypto::s2sk(reduce(secret_key)));
  }

}

