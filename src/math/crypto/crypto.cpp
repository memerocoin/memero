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

#include "crypto.hpp"

#include "tools/common/varint.h"
#include "tools/epee/include/string_tools.h"
#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/int-util.h"

#include "config/cryptonote.hpp"

#include <sodium.h>

#include <cassert>
#include <mutex>
#include <memory>


extern "C" {
#include "crypto-ops.h"
}

namespace crypto {

  ec_point add(const ec_point X, const ec_point Y) {
    ec_point p;
    int r = crypto_core_ed25519_add(p.data, X.data, Y.data);
    if (r != 0) {
      LOG_FATAL("add keys not in main group: " << X << "\n" << Y);
    }

    return p;
  }

  ec_point ec_point::operator+(const ec_point& x) const {
    return add(*this, x);
  }

  ec_point sub(const ec_point X, const ec_point Y) {
    ec_point p;
    int r = crypto_core_ed25519_sub(p.data, X.data, Y.data);
    if (r != 0) {
      LOG_FATAL("sub keys not in main group: " << X << "\n" << Y);
    }

    return p;
  }

  ec_point ec_point::operator-(const ec_point& x) const {
    return sub(*this, x);
  }

  ec_point ec_point::operator*(const uint64_t x) const {
    return mult(*this, int_to_scalar(x));
  }

  ec_scalar ec_scalar::operator+(const ec_scalar& x) const {
    ec_scalar s;
    crypto_core_ed25519_scalar_add(s.data, this->data, x.data);
    return s;
  }

  ec_scalar ec_scalar::operator-(const ec_scalar& x) const {
    ec_scalar s;
    crypto_core_ed25519_scalar_sub(s.data, this->data, x.data);
    return s;
  }

  ec_scalar ec_scalar::operator*(const ec_scalar& x) const {
    ec_scalar s;
    crypto_core_ed25519_scalar_mul(s.data, this->data, x.data);
    return s;
  }

  bool is_valid_point(const ec_point_unsafe x) {
    return crypto_core_ed25519_is_valid_point(x.data);
  }
  /*
   * generate public and secret keys from a random 256-bit integer
   * TODO: allow specifying random value (for wallet recovery)
   *
   */
  std::pair<secret_key, public_key> generate_keys(std::optional<secret_key> recovery_key) {
    const secret_key s = recovery_key ? s2sk(reduce(*recovery_key)) : s2sk(scalarGen());
    return {s, p2pk(multBase(s))};
  }

  bool secret_key_to_public_key(const secret_key &sec, public_key &pub) {
    return 0 == crypto_scalarmult_ed25519_base_noclamp(pub.data, sec.data);
  }

  bool generate_key_derivation
  (
   const ec_point_unsafe &unsafe_key1
   , const secret_key &key2
   , key_derivation &derivation
   ) {
    const auto key1 = maybeSafePoint(unsafe_key1);
    if (!key1) return false;

    // here mult8 is really not needed
    const ec_point p = mult8Safe(mult(*key1, key2));

    derivation = p2derivation(p);

    return true;
  }

  ec_scalar hash_derivation_to_scalar(const key_derivation &derivation, const size_t index) {
    const epee::blob::data hashData =
      epee::blob::data(derivation.data, sizeof(derivation.data))
      + epee::string_tools::string_to_blob(tools::get_varint_data(index));

    return hash_to_scalar(hashData);
  }

  bool derive_public_key
  (
   const key_derivation &derivation
   , const size_t output_index
   , const ec_point_unsafe &unsafe_base
   , public_key &derived_key
   ) {
    const auto base = maybeSafePoint(unsafe_base);
    if (!base) return false;

    const ec_scalar scalar = hash_derivation_to_scalar(derivation, output_index);
    const ec_point derived = multBase(scalar);
    const ec_point r = derived + *base;
    derived_key = p2pk(r);
    return true;
  }

  secret_key derive_secret_key(const key_derivation &derivation, const size_t output_index,
    const secret_key &base)
  {
    assert(is_reduced(base));

    const ec_scalar scalar = hash_derivation_to_scalar(derivation, output_index);
    return s2sk(base + scalar);
  }

  bool derive_subaddress_public_key
  (
   const ec_point_unsafe &unsafe_out_key
   , const key_derivation &derivation
   , const std::size_t output_index,
   public_key &derived_key
   )
  {
    const auto out_key = maybeSafePoint(unsafe_out_key);
    if (!out_key) return false;

    const ec_scalar scalar = hash_derivation_to_scalar(derivation, output_index);

    if (scalar == s_0) return false;

    const ec_point p = multBase(scalar);

    derived_key = p2pk(sub(*out_key, p));
    return true;
  }

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

  ec_scalar hash_to_scalar(const std::span<const uint8_t> x) {
    const auto h = sha3(x);
    return reduce(h2s(h));
  }

  signature generate_signature
  (
   const hash &prefix_hash
   , const public_key &pub
   , const secret_key &sec
   )
  {
    while (true) {
      const ec_scalar k = scalarGen();
      if (k == s_0) continue;

      const ec_point comm = multBase(k);
      const s_comm buf {prefix_hash, pub, comm};
      const ec_scalar sig_c = hash_to_scalar(epee::pod_to_span(buf));

      if (sig_c != s_0)
        continue;

      const ec_scalar sig_r = k - sig_c * sec;

      if (sig_r != s_0)
        continue;

      return
        {
          sig_c
          , sig_r
        };
    }

  }

  bool check_signature(const hash &prefix_hash, const ec_point_unsafe &pub, const signature &sig) {
    const auto p = maybeSafePoint(pub);

    // if (!p) throw std::runtime_error("signature pubkey is invalid");
    if (!p) return false;

    if (is_not_reduced(sig.c) || is_not_reduced(sig.r) || (sig.c != s_0)) {
      return false;
    }

    const ec_point r = mult(*p, sig.c) + multBase(sig.r);

    if (r == identity) return false;

    const s_comm buf { prefix_hash, *p, r };
    const ec_scalar h = hash_to_scalar(epee::pod_to_span(buf));

    return h - sig.c == s_0;
  }

  // Generate a proof of knowledge of `r` such that (`R = rG` and `D = rA`) or (`R = rB` and `D = rA`) via a Schnorr proof
  // This handles use cases for both standard addresses and subaddresses
  //
  // Generates only proofs for InProofV2 and OutProofV2
  signature generate_tx_proof
  (
   const hash &prefix_hash
   , const public_key &R
   , const public_key &A
   , const std::optional<public_key> &B
   , const public_key &D
   , const secret_key &r
   )
  {
    // sanity check

    if (!is_valid_point(R)) throw std::runtime_error("tx pubkey is invalid");
    if (!is_valid_point(A)) throw std::runtime_error("recipient view pubkey is invalid");
    if (B) {
      if (!is_valid_point(*B)) throw std::runtime_error("recipient spend pubkey is invalid");
    }
    if (!is_valid_point(D)) throw std::runtime_error("key derivation is invalid");

    // pick random k
    const ec_scalar k = scalarGen();

    // if B is not present
    static const ec_point zero = {};

    // struct s_comm_2 {
    //   hash msg;
    //   ec_point D;
    //   ec_point X;
    //   ec_point Y;
    //   hash sep; // domain separation
    //   ec_point R;
    //   ec_point A;
    //   ec_point B;
    // };

    const s_comm_2 buf =
      {
        prefix_hash
        , D
        , B ? mult(*B, k) : multBase(k)
        , mult(A, k)
        , sha3(epee::blob::span(config::HASH_KEY_TXPROOF_V2, sizeof(config::HASH_KEY_TXPROOF_V2) - 1))
        , R
        , A
        , B ? *B : zero
      };


    // sig.c = Hs(Msg || D || X || Y || sep || R || A || B)
    // sig.r = k - sig.c*r

    const auto sig_c = hash_to_scalar(epee::pod_to_span(buf));
    return {
      sig_c
      , k - sig_c * r
    };
  }

  bool check_tx_proof
  (
   const hash &prefix_hash
   , const public_key &R
   , const public_key &A
   , const std::optional<public_key> &B
   , const public_key &D
   , const signature &sig
   )
  {
    // sanity check

    if (!is_valid_point(R)) return false;
    if (!is_valid_point(A)) return false;
    if (!is_valid_point(D)) return false;
    if (B && !is_valid_point(*B)) return false;

    if (is_not_reduced(sig.c) || is_not_reduced(sig.r)) return false;

    // compute sig.c*R

    const ec_point cR = mult(R, sig.c);

    const ec_point X = B
      ? mult(*B, sig.r) + cR
      : multBase(sig.r) + cR;

    // compute sig.c*D
    const ec_point cD = mult(D, sig.c);

    // compute sig.r*A
    const ec_point rA = mult(A, sig.r);

    // compute Y = sig.c*D + sig.r*A
    const ec_point Y = cD + rA;

    // Compute hash challenge
    // for v1, c2 = Hs(Msg || D || X || Y)
    // for v2, c2 = Hs(Msg || D || X || Y || sep || R || A || B)

    // if B is not present
    static const ec_point zero = {};

    // struct s_comm_2 {
    //   hash msg;
    //   ec_point D;
    //   ec_point X;
    //   ec_point Y;
    //   hash sep; // domain separation
    //   ec_point R;
    //   ec_point A;
    //   ec_point B;
    // };

    const s_comm_2 buf =
      {
        prefix_hash
        , D
        , X
        , Y
        , sha3(epee::blob::span(config::HASH_KEY_TXPROOF_V2, sizeof(config::HASH_KEY_TXPROOF_V2) - 1))
        , R
        , A
        , B ? *B : zero
      };


    // Hash depends on version
    const ec_scalar c2 = hash_to_scalar(epee::pod_to_span(buf));

    // test if c2 == sig.c
    return c2 - sig.c == s_0;
  }

  ec_point viaF2(const crypto_data x) {
    ge_p2 in;
    ge_fromfe_frombytes_vartime(&in, x.data);
    ec_point out;
    ge_tobytes(out.data, &in);
    return out;
  }


  //generates a random scalar which can be used as a secret key or mask
  ec_scalar scalarGen() {
    ec_scalar s;
    crypto_core_ed25519_scalar_random(s.data);
    return s;
  }

  ec_point multBase(const ec_scalar x) {
    ec_point p;
    const int r = crypto_scalarmult_ed25519_base_noclamp(p.data, x.data);
    if (r != 0) {
      LOG_FATAL("scalar mult base failed");
    }
    return p;
  }


  ec_point mult(const ec_point X, const ec_scalar a) {
    if (a == s_0) {
      return identity;
    }

    ec_point x;
    const int r = crypto_scalarmult_ed25519_noclamp(x.data, a.data, X.data);
    if (r != 0) {
      LOG_FATAL("mult point is not on curve: " << X << "\nresult: " << x);
    }

    return x;
  }

  ec_point mult8Safe(const ec_point X) {
    return X * 8;
  }

  // needed because point can be out of main group
  ec_point mult8(const ec_point_unsafe X) {
    ec_point res;
    ge_p3 in;
    ge_p2 point;
    ge_p1p1 point2;
    ge_p2 p2;

    ge_frombytes_vartime(&in, X.data);
    ge_p3_to_p2(&point, &in);

    ge_mul8(&point2, &point);

    ge_p1p1_to_p2(&p2, &point2);
    ge_tobytes(res.data, &p2);
    return res;
  }

  // multiplicative inverse
  ec_scalar invert(const ec_scalar x)
  {
    ec_scalar r;
    crypto_core_ed25519_scalar_invert(r.data, x.data);
    return r;
  }

  key_image generate_key_image(const public_key &pub, const secret_key &sec) {
    const ec_point h = viaF2(h2p(sha3(pub.data)));
    const ec_point p = mult(mult8(h), sec);
    return p2img(p);
  }

  ec_scalar reduce(const ec_scalar_unnormalized x) {
    unsigned char t[64] = {0};
    std::copy(std::begin(x.data), std::end(x.data), t);

    ec_scalar s;
    crypto_core_ed25519_scalar_reduce(s.data, t);
    return s;
  }

  bool is_reduced(const ec_scalar_unnormalized x) {
    return reduce(x) == x;
  }

  bool is_not_reduced(const ec_scalar_unnormalized x) {
    return !(is_reduced(x));
  }

  std::optional<ec_point> maybeSafePoint(const ec_point_unsafe x) {
    if (is_valid_point(x)) {
      return unsafe_p2p(x);
    } else {
      return {};
    }
  }

  //uint long long to 32 byte key
  ec_scalar int_to_scalar(const uint64_t in) {
    ec_scalar x = {};
    memcpy_swap64le(x.data, &in, 1);
    return x;
  }

  //32 byte key to uint long long
  // if the key holds a value > 2^64
  // then the value in the first 8 bytes is returned
  uint64_t scalar_to_int(const ec_scalar & in) {
    uint64_t vali = 0;
    int j = 0;
    for (j = 7; j >= 0; j--) {
      vali = (uint64_t)(vali * 256 + (unsigned char)in.data[j]);
    }
    return vali;
  }
}

CRYPTO_MAKE_HASHABLE_CPP(public_key)
CRYPTO_MAKE_HASHABLE_CPP(secret_key)
CRYPTO_MAKE_HASHABLE_CPP(key_image)
CRYPTO_MAKE_COMPARABLE_CPP(signature)
