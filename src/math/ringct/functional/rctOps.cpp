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

#include "rctOps.hpp"

#include "cryptonote/basic/cryptonote_format_utils.h"

#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/string_tools.h"

#include <boost/lexical_cast.hpp>

#include <sodium.h>

#include <numeric>



#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

namespace rct {

  rct_point G_(const rct_scalar a) {
    return crypto::multBase(a);
  }

  rct_point H_(const rct_scalar a) {
    return H ^ a;
  }

  rct::rct_point addPoints(const rct_pointS A) {
    return std::reduce
      (
       A.begin()
       , A.end()
       , crypto::identity
       );
  }



  // ct
  rct_point commit(const crypto::ec_scalar_unnormalized mask, const amount_t amount) {
    return G_(crypto::reduce(mask)) + H_(crypto::int_to_scalar(amount));
  }

  rct_point dummyCommit(const amount_t amount) {
    return commit(s_one, amount);
  }



  // hash
  crypto::hash hash_data(const crypto::crypto_data in) {
    return crypto::sha3(in.data);
  }

  rct_scalar hash_to_scalar(const crypto::crypto_data in) {
    return reduce(d2s(h2d(hash_data(in))));
  }

  crypto::hash hash_dataV(const std::span<const crypto::crypto_data> keys) {
    if (keys.empty()) {
      return crypto::sha3({});
    }
    return crypto::sha3(epee::blob::span((const uint8_t*)&keys[0], keys.size() * sizeof(keys[0])));
  }

  rct_scalar hash_dataV_to_scalar(const std::span<const crypto::crypto_data> keys) {
    return reduce(d2s(h2d(hash_dataV(keys))));
  }

  rct_point hash_to_point_via_field(const crypto::crypto_data k) {
    const auto h = h2d(hash_data(k));
    const crypto::ec_point p = viaFieldMult8(h);
    return p;
  }



  // ecdh
  constexpr std::string_view ecdhHashPrefix = "amount";
  crypto::hash derive_secret_key_for_ecdh_amount(const rct_scalar x)
  {
    const epee::blob::data hashData =
      epee::string_tools::string_to_blob(std::string(ecdhHashPrefix))
      + x.blob();

    return crypto::sha3(hashData);
  }

  crypto::crypto_data hash_and_xor_first_8_bytes(const crypto::crypto_data x, const rct_scalar y)
  {
    const crypto::hash h = derive_secret_key_for_ecdh_amount(y);
    crypto::crypto_data r = x;

    for (int i = 0; i < 8; ++i)
      r.data[i] ^= h.data[i];

    return r;
  }

  constexpr std::string_view commitmentMaskPrefix = "commitment_mask";
  rct_scalar get_blinding_factor_from_shared_secret_hash(const rct_scalar x) {
    const epee::blob::data hashData =
      epee::string_tools::string_to_blob(std::string(commitmentMaskPrefix))
      + x.blob();

    return crypto::hash_to_scalar(hashData);
  }
}
