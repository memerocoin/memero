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

#include "rctGen.hpp"

#include "math/ringct/functional/rctOps.hpp"

#include "cryptonote/basic/cryptonote_format_utils.h"

#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/string_tools.h"

#include <boost/lexical_cast.hpp>

#include <sodium.h>

#include <numeric>



#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

namespace rct {
  //Various key generation functions

  //generates a random rct_scalar which can be used as a secret key or mask
  rct_scalar skGen() {
    return s2s(crypto::scalarGen());
  }

  //Generates a vector of secret key
  //Mainly used in testing
  rct_scalarV skvGen(size_t rows ) {
    LOG_ERROR_AND_THROW_UNLESS(rows > 0, "0 keys requested");
    rct_scalarV rv(rows);
    size_t i = 0;
    for (i = 0 ; i < rows ; i++) {
      rv[i] = skGen();
    }
    return rv;
  }

  //generates a random curve point (for testing)
  rct_point pkGen() {
    rct_scalar sk = skGen();
    return multG(sk);
  }

  //generates a random secret and corresponding public key
  std::pair<rct_scalar, rct_point> skpkGen() {
    const rct_scalar sk = skGen();
    return std::make_pair(sk, multG(sk));
  }

  //generates a <secret , public> / Pedersen commitment to the amount
  std::pair<ct_secret_key, ct_public_key> ctskpkGen(amount_t amount) {
    const auto [addr_sk, addr_pk] = skpkGen();
    const auto [blinding_factor_sk, blinding_factor_pk] = skpkGen();

    const rct_scalar am = int_to_scalar(amount);
    const rct_point bH = multH(am);

    return
      {
        {addr_sk, blinding_factor_sk}
        , {addr_pk, blinding_factor_pk + bH}
      };
  }


  //generates a <secret , public> / Pedersen commitment but takes bH as input
  std::pair<ct_secret_key, ct_public_key> ctskpkGen(const rct_point bH) {
    const auto [addr_sk, addr_pk] = skpkGen();
    const auto [blinding_factor_sk, blinding_factor_pk] = skpkGen();

    return
      {
        {addr_sk, blinding_factor_sk}
        , {addr_pk, blinding_factor_pk + bH}
      };
  }

  //generates a random uint long long (for testing)
  amount_t randXmrAmount(const amount_t upperlimit) {
    return scalar_to_int(skGen()) % (upperlimit);
  }
}
