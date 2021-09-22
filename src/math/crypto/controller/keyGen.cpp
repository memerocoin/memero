/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/


#include "keyGen.hpp"

#include "tools/common/varint.h"
#include "tools/epee/include/string_tools.h"
#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/int-util.h"

#include "config/cryptonote.hpp"

#include <sodium.h>

#include <cassert>
#include <mutex>
#include <memory>


extern "C" {
#include "crypto-ops.h"
}

namespace crypto {


  //generates a random rct_scalar which can be used as a secret key or mask
  ec_scalar scalarGen() {
    ec_scalar s;
    crypto_core_ed25519_scalar_random(s.data.data());
    return s;
  }

  ec_point randomPoint() {
    ec_point x;
    crypto_core_ed25519_random(x.data.data());
    return x;
  }

  /*
   * generate public and secret keys from a random 256-bit integer
   * TODO: allow specifying random value (for wallet recovery)
   *
   */
  std::pair<secret_key, public_key> generate_keys(std::optional<secret_key> recovery_key) {
    const secret_key s = recovery_key ? s2sk(reduce(*recovery_key)) : s2sk(scalarGen());
    return {s, to_pk(s)};
  }

  double_schnorr_signature generate_tx_proof
  (
   const hash &h
   , const ec_point_unsafe &R
   , const ec_point_unsafe &A
   , const std::optional<ec_point_unsafe> &base
   , const ec_point_unsafe &D
   , const ec_scalar_unnormalized &r
   )
  {
    // sanity check

    const auto maybeR = maybeSafePoint(R);
    if (!maybeR) throw std::runtime_error("tx pubkey is invalid");

    const auto maybeA = maybeSafePoint(A);
    if (!maybeA) throw std::runtime_error("recipient view pubkey is invalid");

    const auto maybeD = maybeSafePoint(D);
    if (!maybeD) throw std::runtime_error("key derivation is invalid");

    if (base && (!is_safe_point(*base))) {
      throw std::runtime_error("recipient spend pubkey is invalid");
    }
    const auto maybeCustomBase = base ? maybeSafePoint(*base) : std::optional<ec_point>();

    if (is_not_reduced(r)) throw std::runtime_error("invalid secrect key");

    const auto sk = s2sk(reduce(r));

    // keypair (r R) (r D)@A

    const epee::blob::data B_blob = maybeCustomBase ? maybeCustomBase->blob() : epee::blob::data();

    const auto hash_key = epee::string_tools::string_to_blob(config::HASH_KEY_TXPROOF_V3);
    const auto schnorr_1 = generate_schnorr_signature(hash_key + h.blob() + B_blob + maybeR->blob(), sk, maybeCustomBase);
    const auto schnorr_2 = generate_schnorr_signature(hash_key + h.blob() + maybeA->blob() + maybeD->blob(), sk, {*maybeA});

    return {schnorr_1, schnorr_2};
  }


}

