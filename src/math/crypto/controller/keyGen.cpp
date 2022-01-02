/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/


#include "keyGen.hpp"

#include "random.hpp"

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


  //generates a random crypto::ec_scalar which can be used as a secret key or mask
  ec_scalar randomScalar() {
    ec_scalar s;
    crypto_core_ed25519_scalar_random(s.data.data());
    return s;
  }

  std::vector<ec_scalar> randomScalars(size_t n) {
    std::vector<ec_scalar> xs;
    std::generate_n
      (
       std::back_inserter(xs)
       , n
       , randomScalar
       );
    return xs;
  }

  ec_point randomPoint() {
    ec_point x;
    crypto_core_ed25519_random(x.data.data());
    return x;
  }

  uint64_t randomAmount() {
    return crypto::rand<uint64_t>();
  }

  crypto_data randomCryptoData() {
    crypto_data x;
    generate_random_bytes(x.data.data(), x.data.size());
    return x;
  }

  /*
   * generate public and secret keys from a random 256-bit integer
   * TODO: allow specifying random value (for wallet recovery)
   *
   */
  std::pair<secret_key, public_key> generate_keys(std::optional<secret_key> recovery_key) {
    const secret_key s = recovery_key ? s2sk(reduce(*recovery_key)) : s2sk(randomScalar());
    return {s, to_pk(s)};
  }

  // sender holds the private key of the tx output public key
  schnorr_signature generate_tx_proof
  (
   const hash message_hash
   , const std::optional<ec_point_unsafe> view_key_base // spend public key
   , const ec_scalar_unnormalized tx_output_secret_key
   )
  {
    if (view_key_base && (!is_safe_point(*view_key_base))) {
      throw std::runtime_error("recipient spend pubkey is invalid");
    }
    const auto maybe_custom_view_key_base = view_key_base ? maybeSafePoint(*view_key_base) : std::optional<ec_point>();

    if (is_not_reduced(tx_output_secret_key)) throw std::runtime_error("invalid secrect key");

    const auto sk = s2sk(reduce(tx_output_secret_key));

    const auto hash_key = epee::string_tools::string_to_blob(config::HASH_KEY_TX_OUTPUT_SIGNATURES_V1);
    return generate_schnorr_signature(hash_key + message_hash.blob(), sk, maybe_custom_view_key_base);
  }


}

