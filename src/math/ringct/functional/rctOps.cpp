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

#include "rctOps.hpp"

#include "cryptonote/basic/cryptonote_format_utils.h"

#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/string_tools.h"

#include <boost/lexical_cast.hpp>

#include <sodium.h>

#include <numeric>



#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

namespace rct {

  //Various rct_point initialization functions

  //initializes a rct_point matrix;
  //first parameter is rows,
  //second is columns
  rct_pointM rct_pointMInit(size_t rows, size_t cols) {
    rct_pointM rv(cols);
    size_t i = 0;
    for (i = 0 ; i < cols ; i++) {
      rv[i] = rct_pointV(rows);
    }
    return rv;
  }


  //generates C =aG + bH from b, a is given..
  rct_point genC(const rct_scalar a, amount_t amount) {
    return addMultG_H(a, int_to_scalar(amount));
  }

  rct_point dummyCommit(const amount_t amount) {
    rct_scalar am = int_to_scalar(amount);
    rct_point bH = multH(am);
    return G + bH;
  }

  rct_point commit(const amount_t amount, const rct_scalar &mask) {
    return genC(mask, amount);
  }

  //Scalar multiplications of curve points

  rct_scalar normalizeKey(const rct_scalar a) {
    return s2s(crypto::reduce(a));
  }

  //does a * G where a is a rct_scalar and G is the curve basepoint
  rct_point multG(const rct_scalar a) {
    rct_scalar s = normalizeKey(a);
    return p2rct_p(crypto::multBase(s));
  }

  //does a * P where a is a rct_scalar and P is an arbitrary point
  rct_point multP(const rct_point P, const rct_scalar a) {
    rct_scalar s = normalizeKey(a);
    return p2rct_p(crypto::mult(P, s));
  }


  //Computes aH where H= toPoint(sha3(G)), G the basepoint
  rct_point multH(const rct_scalar a) {
    return multP(H, a);
  }

  //Computes 8P
  rct_point multP8(const crypto::ec_point_unsafe P) {
    return p2rct_p(crypto::mult8(P));
  }

  rct_point multP8Safe(const rct_point P) {
    return p2rct_p(crypto::mult8Safe(P));
  }


  //Curve addition / subtractions

  rct::rct_point addPoints(const rct_pointS A) {
    return std::reduce
      (
       A.begin()
       , A.end()
       , rct::identity
       );
  }

  //addPoints2
  //aGbB = aG + bH where a, b are rct_scalars, G is the basepoint and H is the second basepoint
  rct_point addMultG_H(const rct_scalar a, const rct_scalar b) {
    return multG(a) + multH(b);
  }

  //sha3 for a 32 byte key
  crypto::hash hash_key(const crypto::crypto_data in) {
    return crypto::sha3(in.data);
  }

  rct_scalar hash_to_scalar(const crypto::crypto_data in) {
    return s2s(reduce(d2s(h2d(hash_key(in)))));
  }

  crypto::hash hash_keys(const std::span<const crypto::crypto_data> keys) {
    if (keys.empty()) {
      return crypto::sha3({});
    }
    return crypto::sha3(epee::blob::span((const uint8_t*)&keys[0], keys.size() * sizeof(keys[0])));
  }

  rct_scalar hash_keys_to_scalar(const std::span<const crypto::crypto_data> keys) {
    return s2s(reduce(d2s(h2d(hash_keys(keys)))));
  }

  rct_point hash_to_key_via_f2(const crypto::crypto_data k) {
    const auto h = h2d(hash_key(k));
    const crypto::ec_point p = viaF2Mult8(h);
    return p2rct_p(p);
  }

  //Elliptic Curve Diffie Helman: encodes and decodes the amount b and mask a
  // where C= aG + bH

  constexpr std::string_view ecdhHashPrefix = "amount";
  crypto::hash ecdhHash(const crypto::crypto_data x)
  {
    const epee::blob::data hashData =
      epee::string_tools::string_to_blob(std::string(ecdhHashPrefix))
      + epee::blob::data(x.data.begin(), x.data.size());

    return crypto::sha3(hashData);
  }

  crypto::crypto_data xor8(const crypto::crypto_data x, crypto::hash k)
  {
    crypto::crypto_data r = x;
    for (int i = 0; i < 8; ++i)
      r.data[i] ^= k.data[i];

    return r;
  }

  constexpr std::string_view commitmentMaskPrefix = "commitment_mask";
  rct_scalar genCommitmentMask(const crypto::crypto_data x)
  {
    const epee::blob::data hashData =
      epee::string_tools::string_to_blob(std::string(commitmentMaskPrefix))
      + epee::blob::data(x.data.begin(), x.data.size());

    return s2s(crypto::hash_to_scalar(hashData));
  }

  ecdhTuple ecdhEncode(const crypto::ec_scalar_unnormalized amount, const rct_scalar sharedSec) {
    ecdhTuple x = {
      s_zero
      , xor8(amount, ecdhHash(sharedSec))
    };
    return x;
  }

  ecdhTuple ecdhDecode(const crypto::ec_scalar_unnormalized amount, const rct_scalar sharedSec) {
    ecdhTuple x = {
      genCommitmentMask(sharedSec)
      , xor8(amount, ecdhHash(sharedSec))
    };
    return x;
  }
}
