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

#pragma once

#include "math/crypto/functional/key.hpp"

#include "tools/serialization/containers.h"

#include <sodium/crypto_verify_32.h>

#include <span>


namespace rct {

  using pointV = std::vector<crypto::ec_point>;
  using pointS = std::span<const crypto::ec_point>;

  using scalarV = std::vector<crypto::ec_scalar>;
  using scalarS = std::span<const crypto::ec_scalar>;

  using inv8 = crypto::ec_point_unsafe;
  using inv8V = std::vector<inv8>;

  using reconstructed_point = crypto::ec_point;

  const rct::inv8V to_inv8V(const pointS xs);


  struct output_public_data {
    crypto::ec_point output_public_key;
    crypto::ec_point commit;
  };

  struct output_commit {
    crypto::ec_point commit;
  };

  using output_public_dataV = std::vector<output_public_data>;
  using output_public_dataM = std::vector<output_public_dataV>; //matrix of keys (indexed by column first)
  using output_public_dataS = std::span<const output_public_data>;

  //data for passing the amount to the receiver secretly
  struct ecdh_encrypted_data_t {
    uint64_t masked_amount;
  };

  //containers for representing amounts
  using amount_t = uint64_t;

  struct clsag
  {
    scalarV s; // scalars
    crypto::ec_scalar c1;
    crypto::ec_point signer_key_image; // signing key image
    crypto::ec_point blinding_factor_surplus_key_image; // commitment key image
  };

  using LR_V = std::vector<std::pair<crypto::ec_point, crypto::ec_point>>;

  struct Bulletproof
  {
    crypto::ec_point A, S;
    crypto::ec_point T1, T2;
    crypto::ec_scalar taux, mu;
    LR_V LR;
    crypto::ec_scalar a, b, t;
  };

  std::optional<LR_V> zipLR(const pointV L, const pointV R);

  std::pair<pointV, pointV>
  splitLR(const std::span<const std::pair<crypto::ec_point, crypto::ec_point>> LR);
  
}


namespace std
{
  template<> struct hash<crypto::ec_point>
  {
    std::size_t operator()(const crypto::ec_point& x) const noexcept
    {
      boost::hash<std::array<uint8_t,32>> array_hash;
      return array_hash(x.data);
    }
  };
}

