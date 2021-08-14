// Copyright (c) 2020-2021, The Lolnero Project
// Copyright (c) 2016, Monero Research Labs
//
// Author: Shen Noether <shen.noether@gmx.com>
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

#include "curveConstants.hpp"
#include "rctOps.hpp"

#include "cryptonote/basic/cryptonote_format_utils.h"

#include "tools/epee/include/logging.hpp"

#include <boost/lexical_cast.hpp>

#include <sodium.h>

#include <numeric>



#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

namespace rct {

  //Various key initialization functions

  //initializes a key matrix;
  //first parameter is rows,
  //second is columns
  keyM keyMInit(size_t rows, size_t cols) {
    keyM rv(cols);
    size_t i = 0;
    for (i = 0 ; i < cols ; i++) {
      rv[i] = keyV(rows);
    }
    return rv;
  }




  //Various key generation functions

  //generates a random scalar which can be used as a secret key or mask
  scalar skGen() {
    return s2s(crypto::scalarGen());
  }

  //Generates a vector of secret key
  //Mainly used in testing
  scalarV skvGen(size_t rows ) {
    LOG_ERROR_AND_THROW_UNLESS(rows > 0, "0 keys requested");
    scalarV rv(rows);
    size_t i = 0;
    for (i = 0 ; i < rows ; i++) {
      rv[i] = skGen();
    }
    return rv;
  }

  //generates a random curve point (for testing)
  key pkGen() {
    scalar sk = skGen();
    return multG(sk);
  }

  //generates a random secret and corresponding public key
  std::pair<scalar, key> skpkGen() {
    const scalar sk = skGen();
    return std::make_pair(sk, multG(sk));
  }

  //generates C =aG + bH from b, a is given..
  key genC(const scalar a, amount_t amount) {
    return addMultG_H(a, int_to_scalar(amount));
  }

  //generates a <secret , public> / Pedersen commitment to the amount
  std::pair<pri_ctkey, ctkey> ctskpkGen(amount_t amount) {
    pri_ctkey sk;
    ctkey pk;
    std::tie(sk.addr, pk.dest) = skpkGen();
    std::tie(sk.blinding_factor, pk.mask) = skpkGen();

    const scalar am = int_to_scalar(amount);
    const key bH = multH(am);
    pk.mask = pk.mask + bH;
    return std::make_pair(sk, pk);
  }


  //generates a <secret , public> / Pedersen commitment but takes bH as input
  std::pair<pri_ctkey, ctkey> ctskpkGen(const key bH) {
    pri_ctkey sk;
    ctkey pk;
    std::tie(sk.addr, pk.dest) = skpkGen();
    std::tie(sk.blinding_factor, pk.mask) = skpkGen();

    pk.mask = pk.mask + bH;
    return std::make_pair(sk, pk);
  }

  key dummyCommit(const amount_t amount) {
    scalar am = int_to_scalar(amount);
    key bH = multH(am);
    return G + bH;
  }

  key commit(const amount_t amount, const scalar &mask) {
    return genC(mask, amount);
  }

  //generates a random uint long long (for testing)
  amount_t randXmrAmount(const amount_t upperlimit) {
    return scalar_to_int(skGen()) % (upperlimit);
  }

  //Scalar multiplications of curve points

  scalar normalizeKey(const scalar a) {
    return s2s(crypto::reduce(a));
  }

  //does a * G where a is a scalar and G is the curve basepoint
  key multG(const scalar a) {
    scalar s = normalizeKey(a);
    return p2rct(crypto::multBase(s));
  }

  //does a * P where a is a scalar and P is an arbitrary point
  key multP(const key P, const scalar a) {
    scalar s = normalizeKey(a);
    return p2rct(crypto::mult(P, s));
  }


  //Computes aH where H= toPoint(sha3(G)), G the basepoint
  key multH(const scalar a) {
    return multP(H, a);
  }

  //Computes 8P
  key multP8(const crypto::ec_point_unsafe P) {
    return p2rct(crypto::mult8(P));
  }

  //Curve addition / subtractions

  rct::key addPoints(const keyS A) {
    return std::reduce
      (
       A.begin()
       , A.end()
       , rct::identity
       );
  }

  //addPoints2
  //aGbB = aG + bH where a, b are scalars, G is the basepoint and H is the second basepoint
  key addMultG_H(const scalar a, const scalar b) {
    return multG(a) + multH(b);
  }

  //sha3 for a 32 byte key
  crypto::crypto_data hash_key(const crypto::crypto_data in) {
    return crypto::h2d(crypto::sha3(epee::pod_to_span(in)));
  }

  scalar hash_to_scalar(const crypto::crypto_data in) {
    return s2s(reduce(d2s(hash_key(in))));
  }

  crypto::crypto_data hash_keys(const std::span<const crypto::crypto_data> keys) {
    if (keys.empty()) {
      return rct::hash2rct(crypto::sha3({}));
    }
    const auto h = crypto::sha3(epee::blob::span((const uint8_t*)&keys[0], keys.size() * sizeof(keys[0])));
    return h2d(h);
  }

  scalar hash_keys_to_scalar(const std::span<const crypto::crypto_data> keys) {
    return s2s(reduce(d2s(hash_keys(keys))));
  }

  key hash_to_key_via_f2(const crypto::ec_point_unsafe k) {
    const auto h = hash_key(k);
    const crypto::ec_point p = viaF2(h);
    return p2rct(mult8(p));
  }

  //Elliptic Curve Diffie Helman: encodes and decodes the amount b and mask a
  // where C= aG + bH
  key ecdhHash(const key k)
  {
    char data[38];
    memcpy(data, "amount", 6);
    memcpy(data + 6, &k, sizeof(k));
    return hash2rct(crypto::sha3(epee::pod_to_span(data)));
  }
  scalar xor8(const scalar x, const key k)
  {
    scalar r = x;
    for (int i = 0; i < 8; ++i)
      r.data[i] ^= k.data[i];

    return r;
  }

  scalar genCommitmentMask(const key sk)
  {
    char data[15 + sizeof(key)];
    memcpy(data, "commitment_mask", 15);
    memcpy(data + 15, &sk, sizeof(sk));
    key h = rct::hash2rct(crypto::sha3(epee::pod_to_span(data)));
    return s2s(reduce(k2s(h)));
  }

  ecdhTuple ecdhEncode(const scalar amount, const key sharedSec) {
    ecdhTuple x = {
      s_zero
      , xor8(amount, ecdhHash(sharedSec))
    };
    return x;
  }

  ecdhTuple ecdhDecode(const scalar amount, const key sharedSec) {
    ecdhTuple x = {
      genCommitmentMask(sharedSec)
      , xor8(amount, ecdhHash(sharedSec))
    };
    return x;
  }
}
