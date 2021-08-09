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
    const scalar s_zero = ZERO;
    const scalar s_one = ONE;
    const scalar s_two= TWO;
    const scalar s_minus_one = MINUS_ONE;
    const scalar s_eight = EIGHT;
    const scalar s_inv_eight = INV_EIGHT;
    const scalar s_minus_inv_eight= MINUS_INV_EIGHT;
    const scalar s_l = MINUS_INV_EIGHT;

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
    scalar skGen();

    //generates a vector of secret keys of size "int"
    scalarV skvGen(size_t rows );

    //generates a random curve point (for testing)
    key pkGen();
    std::pair<scalar, key> skpkGen();

    //generates a <secret , public> / Pedersen commitment to the amount
    std::pair<pri_ctkey, ctkey> ctskpkGen(amount_t amount);

    //generates C =aG + bH from b, a is random
    key genC(const scalar a, amount_t amount);

    //this one is mainly for testing, can take arbitrary amounts..
    std::pair<pri_ctkey, ctkey> ctskpkGen(const key bH);

    // make a pedersen commitment with given key
    key commit(const amount_t amount, const scalar &mask);

    // make a pedersen commitment with zero key
    key dummyCommit(const amount_t amount);

    //generates a random uint long long
    amount_t randXmrAmount(const amount_t upperlimit);

    //Scalar multiplications of curve points

    //does a * G where a is a scalar and G is the curve basepoint
    key scalarmultBase(const scalar a);

    //does a * P where a is a scalar and P is an arbitrary point
    key scalarmultKey(const key P, const scalar a);

    //Computes aH where H= toPoint(sha3(G)), G the basepoint
    key scalarmultH(const scalar a);

    // multiplies a point by 8
    key multPoint8(const key P);

    //Computes 8P without byte conversion
    ge_p3 multPoint8raw(const key P);

    // checks a is in the main subgroup (ie, not a small one)
    bool isInMainSubgroup(const key a);

    key ge_p3_tokey(const ge_p3 x);

    //Curve addition / subtractions

    //for curve points: AB = A + B
    rct::key addKeys(const key A, const key B);

    rct::key addKeys(const keyS A);

    //aGbB = aG + bH where a, b are scalars, G is the basepoint and H is the second basepoint
    key addScalarMult_G_H(const scalar a, const scalar b);

    //Does some precomputation to make addKeys3 more efficient
    // input B a curve point and output a ge_dsmp which has precomputation applied
    void precomp(ge_dsmp rv, const key B);

    key addKeys_aGbBcC
    (
     const scalar a
     , const scalar b
     , const ge_dsmp B
     , const scalar c
     , const ge_dsmp C
     );

    key addKeys_aAbBcC
    (
     const scalar a
     , const ge_dsmp A
     , const scalar b
     , const ge_dsmp B
     , const scalar c
     , const ge_dsmp C
     );

    //AB = A - B where A, B are curve points
    void subKeys(key &AB, const key &A, const  key &B);

    key hash_key(const key &in);
    scalar hash_to_scalar(const key &in);
    //for mg sigs
    key hash_keys(const keyV &keys);
    scalar hash_keys_to_scalar(const keyV &keys);
    //for ANSL

    void hash_to_p3(ge_p3 &hash8_p3, const key &k);

    //Elliptic Curve Diffie Helman: encodes and decodes the amount b and mask a
    // where C= aG + bH
    scalar genCommitmentMask(const key &sk);
    void ecdhEncode(ecdhTuple & unmasked, const key & sharedSec);
    void ecdhDecode(ecdhTuple & masked, const key & sharedSec);
}
