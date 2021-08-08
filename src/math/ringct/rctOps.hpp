//#define DBG
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

#pragma once

#include "rctTypes.hpp"
#include "curveConstants.hpp"

namespace rct {

    //Various key initialization functions

    // Can't us consteval here or android will panic
    //Creates a zero scalar
    constexpr key zero = Z;
    constexpr key emptyPoint = Z;
    //Creates a zero elliptic curve point
    constexpr key identity = I;

    //initializes a key matrix;
    //first parameter is rows,
    //second is columns
    keyM keyMInit(size_t rows, size_t cols);

    //Various key generation functions

    //generates a random scalar which can be used as a secret key or mask
    key skGen();
    void skGen(key &);

    //generates a vector of secret keys of size "int"
    keyV skvGen(size_t rows );

    //generates a random curve point (for testing)
    key pkGen();
    //generates a random secret and corresponding public key
    void skpkGen(key &sk, key &pk);
    std::tuple<key, key> skpkGen();
    //generates a <secret , public> / Pedersen commitment to the amount
    std::tuple<ctkey, ctkey> ctskpkGen(amount_t amount);
    //generates C =aG + bH from b, a is random
    key genC(const key & a, amount_t amount);
    //this one is mainly for testing, can take arbitrary amounts..
    std::tuple<ctkey, ctkey> ctskpkGen(const key &bH);
    // make a pedersen commitment with given key
    key commit(amount_t amount, const key &mask);
    // make a pedersen commitment with zero key
    key dummyCommit(amount_t amount);
    //generates a random uint long long
    amount_t randXmrAmount(amount_t upperlimit);

    //Scalar multiplications of curve points

    //does a * G where a is a scalar and G is the curve basepoint
    void scalarmultBase(key & aG, const key &a);
    key scalarmultBase(const key & a);
    //does a * P where a is a scalar and P is an arbitrary point
    void scalarmultKey(key &aP, const key &P, const key &a);
    key scalarmultKey(const key &P, const key &a);
    //Computes aH where H= toPoint(sha3(G)), G the basepoint
    key scalarmultH(const key & a);
    // multiplies a point by 8
    key scalarmult8(const key & P);
    void scalarmult8(ge_p3 &res, const key & P);
    // checks a is in the main subgroup (ie, not a small one)
    bool isInMainSubgroup(const key & a);

    key ge_p3_tokey(const ge_p3& x);

    //Curve addition / subtractions

    //for curve points: AB = A + B
    void addKeys(key &AB, const key &A, const key &B);
    rct::key addKeys(const key &A, const key &B);
    rct::key addKeys(const keyV &A);
    //aGbB = aG + bH where a, b are scalars, G is the basepoint and H is the second basepoint
    void addScalarMult_G_H(key &aGbB, const key &a, const key &b);
    //Does some precomputation to make addKeys3 more efficient
    // input B a curve point and output a ge_dsmp which has precomputation applied
    void precomp(ge_dsmp rv, const key &B);

    void addKeys_aGbBcC(key &aGbBcC, const key &a, const key &b, const ge_dsmp B, const key &c, const ge_dsmp C);
    void addKeys_aAbBcC(key &aAbBcC, const key &a, const ge_dsmp A, const key &b, const ge_dsmp B, const key &c, const ge_dsmp C);

    //AB = A - B where A, B are curve points
    void subKeys(key &AB, const key &A, const  key &B);

    key hash_key(const key &in);
    key hash_to_scalar(const key &in);
    //for mg sigs
    key hash_keys(const keyV &keys);
    key hash_keys_to_scalar(const keyV &keys);
    //for ANSL

    void hash_to_p3(ge_p3 &hash8_p3, const key &k);

    //Elliptic Curve Diffie Helman: encodes and decodes the amount b and mask a
    // where C= aG + bH
    key genCommitmentMask(const key &sk);
    void ecdhEncode(ecdhTuple & unmasked, const key & sharedSec);
    void ecdhDecode(ecdhTuple & masked, const key & sharedSec);
}
