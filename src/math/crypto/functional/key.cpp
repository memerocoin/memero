/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "key.hpp"

#include "tools/common/varint.h"
#include "tools/epee/include/string_tools.h"
#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/int-util.h"

#include "config/cryptonote.hpp"

#include <sodium.h>

#include <cassert>
#include <mutex>
#include <memory>

namespace crypto {

  std::optional<public_key> to_maybe_pk(const ec_scalar_unnormalized& sk) noexcept {
    public_key pub;
    const bool r = crypto_scalarmult_ed25519_base_noclamp(pub.data.data(), sk.data.data());
    if (0 == r) {
      return pub;
    } else {
      return {};
    }
  }

  public_key to_pk(const secret_key& sk) noexcept {
    return p2pk(multBase(sk));
  }


  ec_scalar hash_derivation_to_scalar(const key_derivation &derivation, const size_t index) noexcept {
    const epee::blob::data hashData =
      epee::blob::data(derivation.data.data(), derivation.data.size())
      + epee::string_tools::string_to_blob(tools::get_varint_data(index));

    return hash_to_scalar(hashData);
  }

  secret_key derive_secret_key(const key_derivation &derivation, const size_t output_index,
    const secret_key &base) noexcept
  {
    assert(is_reduced(base));

    const ec_scalar rct_scalar = hash_derivation_to_scalar(derivation, output_index);
    return s2sk(base + rct_scalar);
  }

  ec_scalar hash_to_scalar(const std::span<const uint8_t> x) noexcept {
    const auto h = sha3(x);
    return reduce(h2s(h));
  }


  bool verify_schnorr_signature_with_pubkey_data
  (
   const hash prefix_hash
   , const ec_point_unsafe pub
   , const schnorr_signature sig
   ) noexcept {
    const epee::blob::data hash_data(prefix_hash.data.begin(), prefix_hash.data.end());
    const epee::blob::data pub_data(pub.data.begin(), pub.data.end());

    return verify_schnorr_signature(hash_data + pub_data, pub, sig);
  }


  bool check_tx_proof
  (
   const hash &h
   , const public_key &R
   , const public_key &A
   , const std::optional<public_key> &B
   , const public_key &D
   , const double_schnorr_signature &double_sig
   ) noexcept
  {
    // keypair (r R) (r D)@A

    if (B && (!is_safe_point(*B))) return false;

    const epee::blob::data B_blob = B ? B->blob() : epee::blob::data();

    const auto hash_key = epee::string_tools::string_to_blob(config::HASH_KEY_TXPROOF_V3);

    return
      verify_schnorr_signature(hash_key + h.blob() + R.blob() + B_blob, R, double_sig.first, B)
      && verify_schnorr_signature(hash_key + h.blob() + A.blob() + D.blob(), D, double_sig.second, {A});
  }

  key_image derive_key_image(const public_key &pub, const secret_key &sec) noexcept {
    const ec_point h8 = viaFieldMult8(h2p(sha3(pub.data)));
    const ec_point p = h8 ^ sec;
    return p2img(p);
  }


  // only sizeof(uint64_t) bytes of the scalar are used
  ec_scalar int_to_scalar(const uint64_t in) noexcept {
    ec_scalar x = {};
    memcpy_swap64le(x.data.data(), &in, 1);
    return x;
  }

  uint64_t scalar_to_int(const ec_scalar & in) noexcept {
    uint64_t out = 0;
    memcpy_swap64le(&out, in.data.data(), 1);
    return out;
  }

  std::optional<key_derivation> derive_key_derivation
  (
   const ec_point_unsafe &unsafe_point
   , const secret_key &sk
   ) noexcept
  {
    const auto p = maybeSafePoint(unsafe_point);
    if (!p) return {};

    // here mult8 is really not needed
    const key_derivation derivation = p2derivation(mult8Safe(*p ^ sk));

    return derivation;
  }

  std::optional<public_key> derive_tx_output_public_key
  (
   const key_derivation &derivation
   , const size_t output_index
   , const ec_point_unsafe &unsafe_base
   ) noexcept
  {
    const auto base = maybeSafePoint(unsafe_base);
    if (!base) return {};

    const ec_scalar rct_scalar = hash_derivation_to_scalar(derivation, output_index);
    const ec_point derived = multBase(rct_scalar);
    const ec_point r = derived + *base;
    return p2pk(r);
  }

  std::optional<public_key> derive_subaddress_public_key
  (
   const ec_point_unsafe &unsafe_out_key
   , const key_derivation &derivation
   , const std::size_t output_index
   ) noexcept
  {
    const auto out_key = maybeSafePoint(unsafe_out_key);
    if (!out_key) return {};

    const ec_scalar rct_scalar = hash_derivation_to_scalar(derivation, output_index);

    if (rct_scalar == s_0) return {};

    const ec_point p = multBase(rct_scalar);

    return p2pk(*out_key - p);
  }

}

