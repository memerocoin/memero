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

  /*
   * generate public and secret keys from a random 256-bit integer
   * TODO: allow specifying random value (for wallet recovery)
   *
   */
  std::pair<secret_key, public_key> generate_keys(std::optional<secret_key> recovery_key) {
    const secret_key s = recovery_key ? s2sk(reduce(*recovery_key)) : s2sk(scalarGen());
    return {s, p2pk(multBase(s))};
  }

  schnorr_signature generate_signature
  (
   const hash prefix_hash
   , const secret_key sec
   )
  {
    const sig_buf buf {prefix_hash, to_pk(sec)};
    return generate_schnorr_signature(epee::pod_to_span(buf), sec);
  }


  // Generate a proof of knowledge of `r` such that (`R = rG` and `D = rA`) or (`R = rB` and `D = rA`) via a Schnorr proof
  // This handles use cases for both standard addresses and subaddresses
  //
  // Generates only proofs for InProofV2 and OutProofV2
  schnorr_signature generate_tx_proof
  (
   const hash &prefix_hash
   , const public_key &R
   , const public_key &A
   , const std::optional<public_key> &B
   , const public_key &D
   , const secret_key &r
   )
  {
    // sanity check

    if (!is_valid_point(R)) throw std::runtime_error("tx pubkey is invalid");
    if (!is_valid_point(A)) throw std::runtime_error("recipient view pubkey is invalid");
    if (B) {
      if (!is_valid_point(*B)) throw std::runtime_error("recipient spend pubkey is invalid");
    }
    if (!is_valid_point(D)) throw std::runtime_error("key derivation is invalid");

    // pick random k
    const ec_scalar k = scalarGen();

    // if B is not present
    constexpr ec_point zero = {};

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
        , B ? (*B ^ k) : multBase(k)
        , A ^ k
        , sha3(epee::string_tools::string_to_blob(config::HASH_KEY_TXPROOF_V2))
        , R
        , A
        , B ? *B : zero
      };


    // sig.scalar_hash = Hs(Msg || D || X || Y || sep || R || A || B)
    // sig.r = k - sig.scalar_hash*r

    const auto sig_c = hash_to_scalar(epee::pod_to_span(buf));
    return {
      k - sig_c * r
      , sig_c
    };
  }



  //generates a random rct_scalar which can be used as a secret key or mask
  ec_scalar scalarGen() {
    ec_scalar s;
    crypto_core_ed25519_scalar_random(s.data.data());
    return s;
  }

}

