/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#pragma once

#include "group.hpp"
#include "curve25519_cryptonote_extension.hpp"

#include "hash.hpp"
#include "schnorr_signature.hpp"

#include <sodium.h>

#include <boost/functional/hash.hpp>

namespace crypto {
  struct secret_key: ec_scalar{
  };

  struct public_key: ec_point {
  };

  struct tx_output_ecdh_shared_secret: ec_point {};

  struct shared_secret_derived_public_key_image: ec_point {};

  constexpr crypto::public_key null_pkey = {};
  constexpr crypto::secret_key null_skey = {};


  inline const ec_scalar_unnormalized &h2s(const hash &x)        noexcept { return (const ec_scalar&)x; }
  inline const ec_point_unsafe &h2p(const hash &x)               noexcept { return (const ec_point&)x; }
  inline const secret_key &unsafe_h2sk(const hash &x)            noexcept { return (const secret_key&)x; }
  inline const public_key &unsafe_h2pk(const hash &x)            noexcept { return (const public_key&)x; }

  inline const secret_key &s2sk(const ec_scalar &x)              noexcept { return (const secret_key&)x; }
  inline const public_key &p2pk(const ec_point &x)               noexcept { return (const public_key&)x; }
  inline const shared_secret_derived_public_key_image &p2img(const ec_point &x)               noexcept { return (const shared_secret_derived_public_key_image&)x; }
  inline const tx_output_ecdh_shared_secret &p2tx_output_shared_secret(const ec_point &x)   noexcept { return (const tx_output_ecdh_shared_secret&)x; }

  inline const ec_scalar_unnormalized &d2s(const crypto_data &x) noexcept { return (const ec_scalar_unnormalized&)x; }
  inline const ec_point_unsafe &d2p(const crypto_data &x)        noexcept { return (const ec_point_unsafe&)x; }
  inline const crypto_data &h2d(const hash &x)                   noexcept { return (const crypto_data&)x; }
  inline const hash &d2h(const crypto_data &x)                   noexcept { return (const hash&)x; }


  public_key to_pk(const secret_key& sk) noexcept;


  /* Generation and checking of a standard signature.
    */

  using double_schnorr_signature = std::pair<schnorr_signature, schnorr_signature>;

  bool verify_schnorr_signature_with_pubkey_data
  (
   const hash h
   , const ec_point_unsafe pub
   , const schnorr_signature sig
   ) noexcept;

  bool verify_tx_proof
  (
   const hash h
   , const public_key R
   , const public_key A
   , const std::optional<public_key> B
   , const public_key D
   , const double_schnorr_signature sig
   ) noexcept;

  /* To send money to a key:
    * * The sender generates an shared secret derived key and includes it in transaction output.
    * * To spend the money, the receiver generates a key image from it.
    * * Then he selects a bunch of outputs, including the one he spends, and uses them to generate a ring signature.
    * To check the signature, it is necessary to collect all the keys that were used to generate it. To detect double spends, it is necessary to check that each key image is used at most once.
    */
  shared_secret_derived_public_key_image derive_public_key_image(const secret_key) noexcept;

  uint64_t scalar_to_int(const ec_scalar &in) noexcept;
  ec_scalar int_to_scalar(const uint64_t in) noexcept;

  ec_scalar hash_to_scalar(const std::span<const uint8_t>x) noexcept;


  /* To generate an shared secret derived key used to send money to:
   * * The sender generates a new key pair, which becomes the transaction key. The public transaction key is included in "extra" field.
   * * Both the sender and the receiver generate key derivation from the transaction key, the receivers' "view" key and the output index.
   * * The sender uses key derivation and the receivers' "spend" key to derive an shared secret derived public key.
   * * The receiver can either derive the public key (to check that the transaction is addressed to him) or the private key (to spend the money).
   */
  tx_output_ecdh_shared_secret derive_tx_output_ecdh_shared_secret
  (
   const public_key pk
   , const secret_key sk
   ) noexcept;


  ec_scalar hash_tx_output_shared_secret_to_scalar
  (
   const tx_output_ecdh_shared_secret &tx_output_shared_secret
   , const size_t index
   ) noexcept;

  secret_key compute_shared_secret_derived_secret_key_from_spend_secret_key
  (
   const tx_output_ecdh_shared_secret &tx_output_shared_secret
   , const size_t output_index
   , const secret_key &base
   , const ec_scalar offset
   ) noexcept;

  std::optional<public_key> compute_shared_secret_derived_public_key_from_spend_public_key
  (
   const tx_output_ecdh_shared_secret &tx_output_shared_secret
   , const size_t output_index
   , const ec_point_unsafe &unsafe_spend_public_key
   ) noexcept;

  std::optional<public_key> compute_spend_public_key_from_shared_secret_derived_public_key
  (
   const tx_output_ecdh_shared_secret &tx_output_shared_secret
   , const std::size_t output_index
   , const ec_point_unsafe &unsafe_shared_secret_derived_pk
   ) noexcept;

  std::optional<crypto::public_key> maybeNotNull(const crypto::public_key);

  bool verify_keys(const crypto::ec_scalar_unnormalized secret_key, const crypto::public_key public_key);
}

namespace std
{
  template<> struct hash<crypto::public_key>
  {
    std::size_t operator()(crypto::public_key const& x) const noexcept
    {
      boost::hash<std::array<uint8_t,32>> array_hash;
      return array_hash(x.data);
    }
  };

  template<> struct hash<crypto::shared_secret_derived_public_key_image>
  {
    std::size_t operator()(crypto::shared_secret_derived_public_key_image const& x) const noexcept
    {
      boost::hash<std::array<uint8_t,32>> array_hash;
      return array_hash(x.data);
    }
  };

}

