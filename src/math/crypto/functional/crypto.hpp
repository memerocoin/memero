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

#include "group.hpp"
#include "hash.hpp"

#include <sodium.h>

#include <boost/functional/hash.hpp>

namespace crypto {
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

  inline const ec_scalar_unnormalized &h2s(const hash &x) { return (const ec_scalar&)x; }
  inline const ec_point_unsafe &h2p(const hash &x) { return (const ec_point&)x; }
  inline const secret_key &unsafe_h2sk(const hash &x) { return (const secret_key&)x; }
  inline const public_key &unsafe_h2pk(const hash &x) { return (const public_key&)x; }

  inline const secret_key &s2sk(const ec_scalar &x) { return (const secret_key&)x; }
  inline const public_key &p2pk(const ec_point &x) { return (const public_key&)x; }
  inline const key_image &p2img(const ec_point &x) { return (const key_image&)x; }
  inline const key_derivation &p2derivation(const ec_point &x) { return (const key_derivation&)x; }

  inline const ec_scalar_unnormalized &d2s(const crypto_data &x) { return (const ec_scalar_unnormalized&)x; }
  inline const ec_point_unsafe &d2p(const crypto_data &x) { return (const ec_point_unsafe&)x; }
  inline const crypto_data &h2d(const hash &x) { return (const crypto_data&)x; }
  inline const hash &d2h(const crypto_data &x) { return (const hash&)x; }

  ec_scalar hash_derivation_to_scalar(const key_derivation &derivation, const size_t output_index);

  secret_key derive_secret_key(const key_derivation &, const std::size_t, const secret_key &);

  /* Generation and checking of a standard signature.
    */

  struct s_comm {
    hash h;
    ec_point key;
    ec_point comm;
  };

  // Used in v1/v2 tx proofs
  struct s_comm_2 {
    hash msg;
    ec_point D;
    ec_point X;
    ec_point Y;
    hash sep; // domain separation
    ec_point R;
    ec_point A;
    ec_point B;
  };

  bool check_signature(const hash &, const ec_point_unsafe &, const signature &);

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

  ec_point mult8(const ec_point_unsafe X);
  ec_point viaF2Mult8(const crypto_data x);
  ec_scalar hash_to_scalar(const std::span<const uint8_t>x);
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

  template<> struct hash<crypto::key_image>
  {
    std::size_t operator()(crypto::key_image const& x) const noexcept
    {
      boost::hash<std::array<uint8_t,32>> array_hash;
      return array_hash(x.data);
    }
  };

}

