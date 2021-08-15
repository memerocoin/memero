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

#include "hash.hpp"
#include "random.hpp"

#include <sodium.h>
#include <random>

extern "C" {
#include "crypto-ops.h"
}

namespace crypto {
  struct crypto_data {
    std::array<uint8_t, 32> data;
  };

  inline std::ostream &operator <<(std::ostream &o, const crypto::crypto_data &v) {
    epee::hex::append_decode_formatted(o, epee::pod_to_span(v)); return o;
  }

  struct ec_point_unsafe : crypto_data {
    bool operator==(const ec_point_unsafe &x) const { return !crypto_verify_32(data.data(), x.data.data()); }
  };

  struct ec_point : ec_point_unsafe {
    ec_point operator+(const ec_point& x) const;
    ec_point operator-(const ec_point& x) const;
    ec_point operator*(const uint64_t x) const;
  };

  struct ec_scalar_unnormalized : crypto_data {
    bool operator==(const ec_scalar_unnormalized &x) const { return !crypto_verify_32(data.data(), x.data.data()); }
  };

  struct ec_scalar : ec_scalar_unnormalized {
    ec_scalar operator+(const ec_scalar& x) const;
    ec_scalar operator-(const ec_scalar& x) const;
    ec_scalar operator*(const ec_scalar& x) const;
  };

  struct secret_key: ec_scalar{
  };

  struct public_key: ec_point {
  };

  struct key_derivation: ec_point {};

  struct key_image: ec_point {};

  struct signature_unnormalized {
    ec_scalar_unnormalized c, r;
  };

  struct signature {
    ec_scalar c, r;

    bool operator==(const signature_unnormalized &x) const {
      return c == x.c && r == x.r;
    }
  };

  inline std::ostream &operator <<(std::ostream &o, const crypto::signature &v) {
    epee::hex::append_decode_formatted(o, epee::pod_to_span(v)); return o;
  }

  using dataV = std::vector<crypto_data>;
  using dataS = std::span<crypto_data>;


  inline const ec_scalar &h2s(const hash &x) { return (const ec_scalar&)x; }
  inline const ec_point &h2p(const hash &x) { return (const ec_point&)x; }
  inline const secret_key &h2sk(const hash &x) { return (const secret_key&)x; }
  inline const public_key &h2pk(const hash &x) { return (const public_key&)x; }

  inline const secret_key &s2sk(const ec_scalar &x) { return (const secret_key&)x; }
  inline const public_key &p2pk(const ec_point &x) { return (const public_key&)x; }
  inline const key_image &p2img(const ec_point &x) { return (const key_image&)x; }
  inline const key_derivation &p2derivation(const ec_point &x) { return (const key_derivation&)x; }

  inline const ec_scalar_unnormalized &d2s(const crypto_data &x) { return (const ec_scalar_unnormalized&)x; }
  inline const ec_point_unsafe &d2p(const crypto_data &x) { return (const ec_point_unsafe&)x; }
  inline const crypto_data &h2d(const hash &x) { return (const crypto_data&)x; }

  inline const ec_point &unsafe_p2p(const ec_point_unsafe &x) { return (const ec_point&)x; }

  /* Generate a new key pair
    */
  std::pair<secret_key, public_key> generate_keys
  (
     const std::optional<secret_key> recovery_key
   );

  /* Checks a private key and computes the corresponding public key.
    */
  bool secret_key_to_public_key(const secret_key &, public_key &);

  /* To generate an ephemeral key used to send money to:
    * * The sender generates a new key pair, which becomes the transaction key. The public transaction key is included in "extra" field.
    * * Both the sender and the receiver generate key derivation from the transaction key, the receivers' "view" key and the output index.
    * * The sender uses key derivation and the receivers' "spend" key to derive an ephemeral public key.
    * * The receiver can either derive the public key (to check that the transaction is addressed to him) or the private key (to spend the money).
    */
  bool generate_key_derivation(const ec_point_unsafe &, const secret_key &, key_derivation &);

  ec_scalar hash_derivation_to_scalar(const key_derivation &derivation, const size_t output_index);
  bool derive_public_key(const key_derivation &, const std::size_t, const ec_point_unsafe &, public_key &);
  secret_key derive_secret_key(const key_derivation &, const std::size_t, const secret_key &);
  bool derive_subaddress_public_key
  (
   const ec_point_unsafe &out_key
   , const key_derivation &derivation
   , const std::size_t output_index,
   public_key &derived_key
   );

  /* Generation and checking of a standard signature.
    */
  signature generate_signature(const hash &, const public_key &, const secret_key &);

  bool check_signature(const hash &, const ec_point_unsafe &, const signature &);

  /* Generation and checking of a tx proof; given a tx pubkey R, the recipient's view pubkey A, and the key
    * derivation D, the signature proves the knowledge of the tx secret key r such that R=r*G and D=r*A
    * When the recipient's address is a subaddress, the tx pubkey R is defined as R=r*B where B is the recipient's spend pubkey
    */
  signature generate_tx_proof
  (
   const hash &prefix_hash
   , const public_key &R
   , const public_key &A
   , const std::optional<public_key> &B
   , const public_key &D
   , const secret_key &r
   );

  bool check_tx_proof
  (
   const hash &prefix_hash
   , const public_key &R
   , const public_key &A
   , const std::optional<public_key> &B
   , const public_key &D
   , const signature &sig
   );

  /* To send money to a key:
    * * The sender generates an ephemeral key and includes it in transaction output.
    * * To spend the money, the receiver generates a key image from it.
    * * Then he selects a bunch of outputs, including the one he spends, and uses them to generate a ring signature.
    * To check the signature, it is necessary to collect all the keys that were used to generate it. To detect double spends, it is necessary to check that each key image is used at most once.
    */
  key_image generate_key_image(const public_key &, const secret_key &);

  uint64_t scalar_to_int(const ec_scalar &in);
  ec_scalar int_to_scalar(const uint64_t in);

  const crypto::public_key null_pkey = {};
  const crypto::secret_key null_skey = {};

  inline constexpr ec_scalar s_0 = {};
  inline constexpr ec_point identity =
    {{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

  inline constexpr ec_point generator =
    { { 0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
        , 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 } };

  bool is_valid_point(const ec_point_unsafe x);

  //generates a random scalar which can be used as a secret key or mask
  ec_scalar scalarGen();

  std::optional<ec_point> maybeSafePoint(const ec_point_unsafe x);
  ec_point mult(const ec_point X, const ec_scalar);
  ec_point mult8(const ec_point_unsafe X);
  ec_point mult8Safe(const ec_point X);
  ec_point multBase(const ec_scalar);

  ec_scalar invert(const ec_scalar x);

  ec_scalar hash_to_scalar(const std::span<const uint8_t>x);

  ec_point viaF2(const crypto_data x);

  ec_scalar reduce(const ec_scalar_unnormalized x);

  bool is_reduced(const ec_scalar_unnormalized x);
  bool is_not_reduced(const ec_scalar_unnormalized x);

}

CRYPTO_MAKE_HASHABLE_HEADER(public_key)
CRYPTO_MAKE_HASHABLE_HEADER(secret_key)
CRYPTO_MAKE_HASHABLE_HEADER(key_image)
CRYPTO_MAKE_COMPARABLE_HEADER(signature)
