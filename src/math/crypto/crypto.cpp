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

#include "config/cryptonote.hpp"

#include <sodium.h>

#include <cassert>
#include <mutex>
#include <memory>


namespace crypto {

  using std::abort;
  using std::int32_t;
  using std::int64_t;
  using std::size_t;
  using std::uint32_t;
  using std::uint64_t;

  extern "C" {
#include "crypto-ops.h"
  }

  static inline unsigned char *operator &(ec_point &point) {
    return &reinterpret_cast<unsigned char &>(point);
  }

  static inline const unsigned char *operator &(const ec_point &point) {
    return &reinterpret_cast<const unsigned char &>(point);
  }

  static inline unsigned char *operator &(ec_scalar &scalar) {
    return &reinterpret_cast<unsigned char &>(scalar);
  }

  static inline const unsigned char *operator &(const ec_scalar &scalar) {
    return &reinterpret_cast<const unsigned char &>(scalar);
  }

  ec_point ec_point::operator+(const ec_point& x) {
    return add(*this, x);
  }

  void generate_random_bytes(size_t N, uint8_t *bytes)
  {
    randombytes_buf(bytes, N);
  }

  void random32_unbiased(unsigned char *bytes)
  {
    crypto_core_ed25519_scalar_random(bytes);
  }

  /* generate a random 32-byte (256-bit) integer and copy it to res */
  void random_scalar(ec_scalar &res) {
    random32_unbiased((unsigned char*)res.data);
  }

  void hash_to_scalar(const void *data, size_t length, ec_scalar &res) {
    const auto h = sha3(epee::blob::span((const uint8_t*)data, length));
    res = reduce(h2s(h));
  }

  bool is_valid_point(const ec_point x) {
    return crypto_core_ed25519_is_valid_point(x.data);
  }
  /*
   * generate public and secret keys from a random 256-bit integer
   * TODO: allow specifying random value (for wallet recovery)
   *
   */
  secret_key generate_keys(public_key &pub, secret_key &sec, const secret_key& recovery_key, bool recover) {
    sec = recover ? recovery_key : s2sk(random_scalar());
    sec = s2sk(reduce(sec));  // reduce in case second round of keys (sendkeys)

    secret_key_to_public_key(sec, pub);

    return sec;
  }

  bool check_key(const public_key &key) {
    return is_valid_point(key);
  }

  bool secret_key_to_public_key(const secret_key &sec, public_key &pub) {
    return 0 == crypto_scalarmult_ed25519_base_noclamp(pub.data, sec.data);
  }

  ec_point multBase(const ec_scalar x) {
    ec_point p;
    const int r = crypto_scalarmult_ed25519_base_noclamp(p.data, x.data);
    if (r != 0) {
      LOG_FATAL("scalar mult base failed");
    }
    return p;
  }

  ec_point add(const ec_point X, const ec_point Y) {
    ec_point p;
    int r = crypto_core_ed25519_add(p.data, X.data, Y.data);
    if (r != 0) {
      LOG_FATAL("add keys not in main group: " << X << "\n" << Y);
    }

    return p;
  }

  ec_point sub(const ec_point X, const ec_point Y) {
    ec_point p;
    int r = crypto_core_ed25519_sub(p.data, X.data, Y.data);
    if (r != 0) {
      LOG_FATAL("sub keys not in main group: " << X << "\n" << Y);
    }

    return p;
  }

  bool generate_key_derivation(const public_key &key1, const secret_key &key2, key_derivation &derivation) {
    if (!is_valid_point(key1)) return false;

    // here mult8 is really not needed
    ec_point p = mult8(mult(key1, key2));

    derivation = p2derivation(p);

    return true;
  }

  constexpr size_t output_index_buffer_size = (sizeof(size_t) * 8 + 6) / 7;

  void hash_derivation_to_scalar(const key_derivation &derivation, const size_t index, ec_scalar &res) {
    struct {
      key_derivation derivation;
      char output_index_buffer[output_index_buffer_size];
    } buf;

    char *end = buf.output_index_buffer;
    buf.derivation = derivation;
    tools::write_varint(end, index);
    assert(end <= buf.output_index_buffer + output_index_buffer_size);
    hash_to_scalar(&buf, end - reinterpret_cast<char *>(&buf), res);
  }

  bool derive_public_key(const key_derivation &derivation, const size_t output_index,
    const public_key &base, public_key &derived_key) {
    if (!is_valid_point(base)) return false;

    ec_scalar scalar;
    hash_derivation_to_scalar(derivation, output_index, scalar);
    const ec_point derived = multBase(scalar);
    const ec_point r = add(derived, base);
    derived_key = p2pk(r);
    return true;
  }

  void derive_secret_key(const key_derivation &derivation, const size_t output_index,
    const secret_key &base, secret_key &derived_key) {
    ec_scalar scalar;
    assert(sc_check(&base) == 0);
    hash_derivation_to_scalar(derivation, output_index, scalar);
    sc_add(&(derived_key), &(base), &scalar);
  }

  bool derive_subaddress_public_key
  (
   const public_key &out_key
   , const key_derivation &derivation
   , const std::size_t output_index,
   public_key &derived_key
   )
  {
    if (!is_valid_point(out_key)) return false;

    ec_scalar scalar;
    hash_derivation_to_scalar(derivation, output_index, scalar);

    if (scalar == s_0) return false;

    const ec_point p = multBase(scalar);

    derived_key = p2pk(sub(out_key, p));
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

  ec_scalar random_scalar() {
    ec_scalar x;
    random_scalar(x);
    return x;
  }

  ec_scalar hash_to_scalar(const std::span<const uint8_t> x) {
    ec_scalar s;
    hash_to_scalar(x.data(), x.size(), s);
    return s;
  }

  void generate_signature(const hash &prefix_hash, const public_key &pub, const secret_key &sec, signature &sig) {
    while (true) {
      const ec_scalar k = random_scalar();
      if (k == s_0) continue;

      const ec_point comm = multBase(k);
      const s_comm buf {prefix_hash, pub, comm};
      const ec_scalar sig_c = hash_to_scalar(epee::pod_to_span(buf));

      if (!sc_isnonzero(sig_c.data))
        continue;

      ec_scalar sig_r;
      sc_mulsub(&sig.r, &sig.c, &sec, &k);

      if (!sc_isnonzero(sig_r.data))
        continue;

      sig.c = sig_c;
      sig.r = sig_r;
      break;
    }

  }

  bool check_signature(const hash &prefix_hash, const public_key &pub, const signature &sig) {
    assert(check_key(pub));
    if (!is_valid_point(pub)) return false;

    if (sc_check(&sig.c) != 0 || sc_check(&sig.r) != 0 || !sc_isnonzero(&sig.c)) {
      return false;
    }

    const ec_point r = add(mult(pub, sig.c), multBase(sig.r));

    if (r == identity) return false;

    const s_comm buf { prefix_hash, pub, r };
    const ec_scalar h = hash_to_scalar(epee::pod_to_span(buf));

    ec_scalar s;
    sc_sub(&s, &h, &sig.c);

    return sc_isnonzero(&s) == 0;
  }

  // Generate a proof of knowledge of `r` such that (`R = rG` and `D = rA`) or (`R = rB` and `D = rA`) via a Schnorr proof
  // This handles use cases for both standard addresses and subaddresses
  //
  // Generates only proofs for InProofV2 and OutProofV2
  void generate_tx_proof
  (
   const hash &prefix_hash
   , const public_key &R
   , const public_key &A
   , const std::optional<public_key> &B
   , const public_key &D
   , const secret_key &r
   , signature &sig
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
    ec_scalar k;
    random_scalar(k);

    // if B is not present
    static const ec_point zero = {};

    s_comm_2 buf;
    buf.msg = prefix_hash;
    buf.D = D;
    buf.R = R;
    buf.A = A;

    if (B)
        buf.B = *B;
    else
        buf.B = zero;

    buf.sep = sha3(epee::blob::span(config::HASH_KEY_TXPROOF_V2, sizeof(config::HASH_KEY_TXPROOF_V2) - 1));

    if (B)
    {
      // compute X = k*B
      buf.X = mult(*B, k);
    }
    else
    {
      // compute X = k*G
      buf.X = multBase(k);
    }

    // compute Y = k*A
    buf.Y = mult(A, k);

    // sig.c = Hs(Msg || D || X || Y || sep || R || A || B)
    hash_to_scalar(&buf, sizeof(buf), sig.c);

    // sig.r = k - sig.c*r
    sc_mulsub(&sig.r, &sig.c, &(r), &k);

    memwipe(&k, sizeof(k));
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

    if (sc_check(&sig.c) != 0 || sc_check(&sig.r) != 0) return false;

    // compute sig.c*R

    const ec_point cR = mult(R, sig.c);

    const ec_point X = B
      ? add(mult(*B, sig.r), cR)
      : add(multBase(sig.r), cR);

    // compute sig.c*D
    const ec_point cD = mult(D, sig.c);

    // compute sig.r*A
    const ec_point rA = mult(A, sig.r);

    // compute Y = sig.c*D + sig.r*A
    const ec_point Y = add(cD, rA);

    // Compute hash challenge
    // for v1, c2 = Hs(Msg || D || X || Y)
    // for v2, c2 = Hs(Msg || D || X || Y || sep || R || A || B)

    // if B is not present
    static const ec_point zero = {};

    s_comm_2 buf;
    buf.msg = prefix_hash;
    buf.D = D;
    buf.R = R;
    buf.A = A;
    if (B)
        buf.B = *B;
    else
        buf.B = zero;

    buf.sep = sha3(epee::blob::span(config::HASH_KEY_TXPROOF_V2, sizeof(config::HASH_KEY_TXPROOF_V2) - 1));

    buf.X = X;
    buf.Y = Y;

    ec_scalar c2;

    // Hash depends on version
    hash_to_scalar(&buf, sizeof(s_comm_2), c2);

    // test if c2 == sig.c
    sc_sub(&c2, &c2, &sig.c);
    return sc_isnonzero(&c2) == 0;
  }

  ec_point viaF2(const ec_point x) {
    ge_p2 in;
    ge_fromfe_frombytes_vartime(&in, x.data);
    ec_point out;
    ge_tobytes(&out, &in);
    return out;
  }

  ec_point mult(const ec_point X, const ec_scalar a) {
    ec_point x;
    if (a == s_0) {
      return identity;
    }

    const int r = crypto_scalarmult_ed25519_noclamp(x.data, a.data, X.data);
    if (r != 0) {
      LOG_FATAL("mult point is not on curve: " << X << "\nresult: " << x);
    }

    return x;
  }

  // needed because point can be out of main group
  ec_point mult8(const ec_point X) {
    ec_point res;
    ge_p3 in;
    ge_p2 point;
    ge_p1p1 point2;
    ge_p3 p3;

    ge_frombytes_vartime(&in, X.data);
    ge_p3_to_p2(&point, &in);

    ge_mul8(&point2, &point);

    ge_p1p1_to_p3(&p3, &point2);
    ge_p3_tobytes(res.data, &p3);
    return res;
  }

  ge_p3 p3FromPoint(const ec_point x) {
    ge_p3 p;
    ge_frombytes_vartime(&p, x.data);
    return p;
  }

  void generate_key_image(const public_key &pub, const secret_key &sec, key_image &image) {
    const ec_point h = viaF2(h2p(sha3(epee::pod_to_span(pub))));
    const ec_point p = mult(mult8(h), sec);
    image = p2img(p);
  }

  ec_scalar reduce(const ec_scalar x) {
    unsigned char t[64] = {0};
    std::copy(std::begin(x.data), std::end(x.data), t);

    ec_scalar s;
    crypto_core_ed25519_scalar_reduce(s.data, t);
    return s;
  }
}

CRYPTO_MAKE_HASHABLE_CPP(public_key)
CRYPTO_MAKE_HASHABLE_CPP(secret_key)
CRYPTO_MAKE_HASHABLE_CPP(key_image)
CRYPTO_MAKE_COMPARABLE_CPP(signature)
