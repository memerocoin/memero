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

  bool validate_schnorr_signature
  (
   const epee::blob::span message
   , const ec_point_unsafe pub
   , const signature sig
   )
  {
    const auto p = maybeSafePoint(pub);
    if (!p) return false;

    if (is_not_reduced(sig.hashed_scalar) || is_not_reduced(sig.r) || (sig.hashed_scalar == s_0)) {
      return false;
    }

    const ec_point r = (*p ^ sig.hashed_scalar) + multBase(sig.r);

    if (r == identity) return false;

    epee::blob::data hash_data(message.data(), message.size());
    const auto pub_span = epee::pod_to_span(*p);

    std::transform
      (
       pub_span.begin()
       , pub_span.end()
       , std::back_inserter(hash_data)
       , std::identity()
       );

    return sig.hashed_scalar == hash_to_scalar(hash_data);
  }

}
