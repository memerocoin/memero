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
#include "zeroCommitment.hpp"

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
        scalar sk;
        crypto::random32_unbiased(sk.bytes);
        return sk;
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
        return scalarmultBase(sk);
    }

    //generates a random secret and corresponding public key
    std::pair<scalar, key> skpkGen() {
        const scalar sk = skGen();
        return std::make_pair(sk, scalarmultBase(sk));
    }

    //generates C =aG + bH from b, a is given..
    key genC(const scalar a, amount_t amount) {
        return addScalarMult_G_H(a, int_to_scalar(amount));
    }

    //generates a <secret , public> / Pedersen commitment to the amount
    std::pair<pri_ctkey, ctkey> ctskpkGen(amount_t amount) {
        pri_ctkey sk;
        ctkey pk;
        std::tie(sk.addr, pk.dest) = skpkGen();
        std::tie(sk.blinding_factor, pk.mask) = skpkGen();

        const scalar am = int_to_scalar(amount);
        const key bH = scalarmultH(am);
        pk.mask = addKeys(pk.mask, bH);
        return std::make_pair(sk, pk);
    }


    //generates a <secret , public> / Pedersen commitment but takes bH as input
    std::pair<pri_ctkey, ctkey> ctskpkGen(const key bH) {
        pri_ctkey sk;
        ctkey pk;
        std::tie(sk.addr, pk.dest) = skpkGen();
        std::tie(sk.blinding_factor, pk.mask) = skpkGen();

        pk.mask = addKeys(pk.mask, bH);
        return std::make_pair(sk, pk);
    }

    key dummyCommit(const amount_t amount) {
        scalar am = int_to_scalar(amount);
        key bH = scalarmultH(am);
        return addKeys(G, bH);
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
      scalar k = a;
      sc_reduce32(k.bytes);
      return k;
    }

    //does a * G where a is a scalar and G is the curve basepoint
    key scalarmultBase(const scalar a) {
      scalar k = normalizeKey(a);
      key aG;

      // no need to check since a can be 0 in tests
      [[maybe_unused]] int _ = crypto_scalarmult_ed25519_base_noclamp(aG.bytes, k.bytes);

      return aG;
    }

    //does a * P where a is a scalar and P is an arbitrary point
    key scalarmultKey(const key P, const scalar a) {
      scalar s = normalizeKey(a);
      LOG_WARNING_AND_THROW_UNLESS(!sodium_is_zero(s.bytes, 32), "scalar key is zero");

      key k;
      int r = crypto_scalarmult_ed25519_noclamp(k.bytes, s.bytes, P.bytes);
      LOG_WARNING_AND_THROW_UNLESS(r == 0, "scalar mult key not in subgroup");

      return k;
    }


    //Computes aH where H= toPoint(sha3(G)), G the basepoint
    key scalarmultH(const scalar a) {
      scalar s = normalizeKey(a);
      key k;

      // no need to check since a can be 0 in tests, and H is on main group
      [[maybe_unused]] int _ = crypto_scalarmult_ed25519_noclamp(k.bytes, s.bytes, H.bytes);

      return k;
    }

    //Computes 8P
    key multPoint8(const key P) {
        ge_p3 p3;
        LOG_WARNING_AND_THROW_UNLESS(ge_frombytes_vartime(&p3, P.bytes) == 0, "ge_frombytes_vartime failed at "+boost::lexical_cast<std::string>(__LINE__));
        ge_p2 p2;
        ge_p3_to_p2(&p2, &p3);
        ge_p1p1 p1;
        ge_mul8(&p1, &p2);
        ge_p1p1_to_p2(&p2, &p1);
        rct::key res;
        ge_tobytes(res.bytes, &p2);
        return res;
    }

    //Computes 8P without byte conversion
    ge_p3 multPoint8raw(const key P)
    {
        ge_p3 res;
        ge_p3 p3;
        LOG_WARNING_AND_THROW_UNLESS(ge_frombytes_vartime(&p3, P.bytes) == 0, "ge_frombytes_vartime failed at "+boost::lexical_cast<std::string>(__LINE__));
        ge_p2 p2;
        ge_p3_to_p2(&p2, &p3);
        ge_p1p1 p1;
        ge_mul8(&p1, &p2);
        ge_p1p1_to_p3(&res, &p1);
        return res;
    }

    //Computes lA where l is the curve order
    bool isInMainSubgroup(const key A) {
        return 1 == crypto_core_ed25519_is_valid_point(A.bytes);
    }

    key ge_p3_tokey(const ge_p3 x) {
      key k;
      ge_p3_tobytes(k.bytes, &x);
      return k;
    }

    //Curve addition / subtractions

    //for curve points: AB = A + B
    rct::key addKeys(const key A, const key B) {
      key k;
      int r = crypto_core_ed25519_add(k.bytes, A.bytes, B.bytes);
      LOG_WARNING_AND_THROW_UNLESS(r == 0, "add keys not in main group");

      return k;
    }

    rct::key addKeys(const keyS A) {
      return std::accumulate
        (
         A.begin()
         , A.end()
         , rct::identity
         , [](const auto x, const auto y) { return addKeys(x, y); }
         );
    }

    //addKeys2
    //aGbB = aG + bH where a, b are scalars, G is the basepoint and H is the second basepoint
    key addScalarMult_G_H(const scalar &a, const scalar &b) {
      return addKeys(scalarmultBase(a), scalarmultH(b));
    }

    //Does some precomputation to make addKeys3 more efficient
    // input B a curve point and output a ge_dsmp which has precomputation applied
    void precomp(ge_dsmp rv, const key & B) {
        ge_p3 B2;
        LOG_WARNING_AND_THROW_UNLESS(ge_frombytes_vartime(&B2, B.bytes) == 0, "ge_frombytes_vartime failed at "+boost::lexical_cast<std::string>(__LINE__));
        ge_dsm_precomp(rv, &B2);
    }

    // addKeys_aGbBcC
    // computes aG + bB + cC
    // G is the fixed basepoint and B,C require precomputation
    void addKeys_aGbBcC(key &aGbBcC, const scalar &a, const scalar &b, const ge_dsmp B, const scalar &c, const ge_dsmp C) {
        ge_p2 rv;
        ge_triple_scalarmult_base_vartime(&rv, a.bytes, b.bytes, B, c.bytes, C);
        ge_tobytes(aGbBcC.bytes, &rv);
    }

    // addKeys_aAbBcC
    // computes aA + bB + cC
    // A,B,C require precomputation
    void addKeys_aAbBcC(key &aAbBcC, const scalar &a, const ge_dsmp A, const scalar &b, const ge_dsmp B, const scalar &c, const ge_dsmp C) {
        ge_p2 rv;
        ge_triple_scalarmult_precomp_vartime(&rv, a.bytes, A, b.bytes, B, c.bytes, C);
        ge_tobytes(aAbBcC.bytes, &rv);
    }

    //subtract Keys (subtracts curve points)
    //AB = A - B where A, B are curve points
    void subKeys(key & AB, const key &A, const key &B) {
      int r = crypto_core_ed25519_sub(AB.bytes, A.bytes, B.bytes);
      LOG_WARNING_AND_THROW_UNLESS(r == 0, "sub keys not in main group");
    }

    //sha3 for a 32 byte key
    key hash_key(const key & in) {
        return hash2rct(crypto::sha3(epee::pod_to_span(in)));
    }

    scalar hash_to_scalar(const key & in) {
      scalar hash = k2s(hash_key(in));
      sc_reduce32(hash.bytes);
      return hash;
    }

    key hash_keys(const keyV &keys) {
      if (keys.empty()) {
        return rct::hash2rct(crypto::sha3({}));
      }
      const auto h = crypto::sha3(epee::blob::span((const uint8_t*)&keys[0], keys.size() * sizeof(keys[0])));
      return hash2rct(h);
    }

    scalar hash_keys_to_scalar(const keyV &keys) {
        scalar rv = k2s(hash_keys(keys));
        sc_reduce32(rv.bytes);
        return rv;
    }

    // Hash a key to p3 representation
    void hash_to_p3(ge_p3 &hash8_p3, const key &k) {
      key h = hash_key(k);
      ge_p2 hash_p2;
      ge_fromfe_frombytes_vartime(&hash_p2, h.bytes);
      ge_p1p1 hash8_p1p1;
      ge_mul8(&hash8_p1p1, &hash_p2);
      ge_p1p1_to_p3(&hash8_p3, &hash8_p1p1);
    }

    //Elliptic Curve Diffie Helman: encodes and decodes the amount b and mask a
    // where C= aG + bH
    static key ecdhHash(const key &k)
    {
        char data[38];
        memcpy(data, "amount", 6);
        memcpy(data + 6, &k, sizeof(k));
        return hash2rct(crypto::sha3(epee::pod_to_span(data)));
    }
    static void xor8(scalar &v, const key &k)
    {
        for (int i = 0; i < 8; ++i)
            v.bytes[i] ^= k.bytes[i];
    }
    scalar genCommitmentMask(const key &sk)
    {
        char data[15 + sizeof(key)];
        memcpy(data, "commitment_mask", 15);
        memcpy(data + 15, &sk, sizeof(sk));
        key h = rct::hash2rct(crypto::sha3(epee::pod_to_span(data)));
        scalar s = k2s(h);
        sc_reduce32(s.bytes);
        return s;
    }

    void ecdhEncode(ecdhTuple & unmasked, const key & sharedSec) {
        //encode
        unmasked.mask = s_zero;
        xor8(unmasked.amount, ecdhHash(sharedSec));
    }

    void ecdhDecode(ecdhTuple & masked, const key & sharedSec) {
        //decode
        masked.mask = genCommitmentMask(sharedSec);
        xor8(masked.amount, ecdhHash(sharedSec));
    }
}
