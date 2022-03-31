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
#include "tools/epee/functional/int-util.hpp"

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

}

