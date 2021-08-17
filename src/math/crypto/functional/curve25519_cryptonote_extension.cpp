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

#include "curve25519_cryptonote_extension.hpp"

extern "C" {
#include "crypto-ops.h"
}

namespace crypto {
  ec_point_unsafe viaF2(const crypto_data x) {
    ge_p2 in;
    ge_fromfe_frombytes_vartime(&in, x.data.data());
    ec_point out;
    ge_tobytes(out.data.data(), &in);
    return out;
  }


  ec_point viaF2Mult8(const crypto_data x) {
    return mult8(viaF2(x));
  }

  // needed because point can be out of main group
  ec_point mult8(const ec_point_unsafe X) {
    ge_p3 in;
    ge_frombytes_vartime(&in, X.data.data());

    ge_p2 point;
    ge_p3_to_p2(&point, &in);

    ge_p1p1 point2;
    ge_mul8(&point2, &point);

    ge_p2 p2;
    ge_p1p1_to_p2(&p2, &point2);

    ec_point res;
    ge_tobytes(res.data.data(), &p2);
    return res;
  }

}
