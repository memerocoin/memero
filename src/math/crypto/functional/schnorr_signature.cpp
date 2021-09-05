/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "schnorr_signature.hpp"
#include "key.hpp" // hash_to_scalar

#include "tools/epee/include/string_tools.h"

#include "config/cryptonote.hpp"

namespace crypto {

  bool verify_schnorr_signature
  (
   const epee::blob::span message
   , const ec_point_unsafe pub
   , const schnorr_signature sig
   , const std::optional<ec_point_unsafe> base
   )
  {
    /*
        given
          * sec/pub
          * k/K
        key pairs

        from the generator function:

        s = k - hash(m, K) * sec
          = k - scalar_hash * sec

        we know:
        1. m = message
        2. pub
        3. sig = (s, scalar_hash)

        multiply both ends of the equation by G:

        sG = (k - scalar_hash * sec) G
           = kG - scalar_hash (sec G)
           = K - scalar_hash pub

        so K = sG + scalar_hash pub

        We know K now.

        use K to compute scalar_hash as in:

        scalar_hash = hash(m, K), and compare the result from sig



        Why:

        The reason that this is unforgeable, which means that only the person with
        access to sec can produce such signature (s, scalar_hash), is that
        there's no obvious way to produce another signature that satisfies this
        check without knowing sec, that is, to sum up:

          sig.scalar_hash = hash(m, sig.s G + sig.scalar_hash pub)

        Or another (s, k) from which scalar_hash can be derived, in which case
        one needs to solve

          S = K - derived_scalar_hash pub

        where S = sG, K = kG with either a guessed s or k.
    */

    const auto pk = maybeSafePoint(pub);
    if (!pk) return false;

    if (!sig.is_reduced()) return false;

    if (base && (!is_safe_point(*base))) return false;
    const auto maybeCustomBase = base ? maybeSafePoint(*base) : std::optional<ec_point>();


    const ec_point K = (maybeCustomBase ? *maybeCustomBase ^ sig.s : multBase(sig.s)) + (*pk ^ sig.scalar_hash);

    const epee::blob::data message_data(message.begin(), message.end());

    const ec_scalar scalar_hash = hash_to_scalar(message_data + K.blob());

    return sig.scalar_hash == scalar_hash;
  }

}
