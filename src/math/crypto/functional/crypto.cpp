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

namespace crypto {

  ec_scalar hash_derivation_to_scalar(const key_derivation &derivation, const size_t index) {
    const epee::blob::data hashData =
      epee::blob::data(derivation.data.data(), derivation.data.size())
      + epee::string_tools::string_to_blob(tools::get_varint_data(index));

    return hash_to_scalar(hashData);
  }

  secret_key derive_secret_key(const key_derivation &derivation, const size_t output_index,
    const secret_key &base)
  {
    assert(is_reduced(base));

    const ec_scalar rct_scalar = hash_derivation_to_scalar(derivation, output_index);
    return s2sk(base + rct_scalar);
  }

  ec_scalar hash_to_scalar(const std::span<const uint8_t> x) {
    const auto h = sha3(x);
    return reduce(h2s(h));
  }

  bool check_signature(const hash &prefix_hash, const ec_point_unsafe &pub, const signature &sig) {
    const auto p = maybeSafePoint(pub);

    // if (!p) throw std::runtime_error("signature pubkey is invalid");
    if (!p) return false;

    if (is_not_reduced(sig.c) || is_not_reduced(sig.r) || (sig.c == s_0)) {
      return false;
    }

    const ec_point r = mult(*p, sig.c) + multBase(sig.r);

    if (r == identity) return false;

    const s_comm buf { prefix_hash, *p, r };
    const ec_scalar h = hash_to_scalar(epee::pod_to_span(buf));

    return h - sig.c == s_0;
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

  key_image generate_key_image(const public_key &pub, const secret_key &sec) {
    const ec_point h8 = viaF2Mult8(h2p(sha3(pub.data)));
    const ec_point p = mult(h8, sec);
    return p2img(p);
  }


  //uint long long to 32 byte key
  ec_scalar int_to_scalar(const uint64_t in) {
    ec_scalar x = {};
    memcpy_swap64le(x.data.data(), &in, 1);
    return x;
  }

  //32 byte key to uint long long
  // if the key holds a value > 2^64
  // then the value in the first 8 bytes is returned
  uint64_t scalar_to_int(const ec_scalar & in) {
    uint64_t vali = 0;
    int j = 0;
    for (j = 7; j >= 0; j--) {
      vali = (uint64_t)(vali * 256 + (unsigned char)in.data.data()[j]);
    }
    return vali;
  }
}

