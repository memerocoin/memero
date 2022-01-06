/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "curve25519_cryptonote_extension.hpp"

#include <cstring>

extern "C" {
#include "crypto-ops.h"
}

namespace crypto {
  // needed because point can be out of main group
  ec_point mult8(const ec_point_unsafe X) noexcept {
    ge_p3 p3_in;
    ge_frombytes_vartime(&p3_in, X.data.data());

    ge_p2 p2_in;
    ge_p3_to_p2(&p2_in, &p3_in);

    ge_p1p1 p1_8 ;
    ge_mul8(&p1_8, &p2_in);

    ge_p2 p2_out;
    ge_p1p1_to_p2(&p2_out, &p1_8);

    ec_point res;
    ge_tobytes(res.data.data(), &p2_out);
    return res;
  }

  ec_point_unsafe viaField(const crypto_data x) noexcept {
    ge_p2 p2_in;
    ge_fromfe_frombytes_vartime(&p2_in, x.data.data());

    ec_point out;
    ge_tobytes(out.data.data(), &p2_in);
    return out;
  }


  ec_point viaFieldMult8(const crypto_data x) noexcept {
    return mult8(viaField(x));
  }


}

extern "C" {
  void viaFieldMult8(const uint8_t* x, uint8_t* y) {
    crypto::crypto_data in{};
    std::memcpy(in.data.data(), x, in.data.size());
    const auto out = viaFieldMult8(in);
    std::memcpy(y, out.data.data(), out.data.size());
  }
}
