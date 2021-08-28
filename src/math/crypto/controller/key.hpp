// Copyright (c) 2021, The Lolnero Project
// Copyright (c) 2014-2020, The Monero Project
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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include "../functional/key.hpp"

namespace crypto {
  //generates a random rct_scalar which can be used as a secret key or mask
  ec_scalar scalarGen();

  /* Checks a private key and computes the corresponding public key.
    */
  bool secret_key_to_public_key(const secret_key &, public_key &);

  std::optional<public_key> derive_tx_public_key
  (
   const key_derivation &derivation
   , const size_t output_index
   , const ec_point_unsafe &unsafe_base
   );

  bool derive_subaddress_public_key
  (
   const ec_point_unsafe &unsafe_out_key
   , const key_derivation &derivation
   , const std::size_t output_index,
   public_key &derived_key
   );


  /* Generate a new key pair
   */
  std::pair<secret_key, public_key> generate_keys
  (
   const std::optional<secret_key> recovery_key
   );

  /* Generation and checking of a standard signature.
    */
  signature generate_signature(const hash &, const public_key &, const secret_key &);

  /* Generation and checking of a tx proof; given a tx pubkey R, the recipient's view pubkey A, and the key
    * derivation D, the signature proves the knowledge of the tx secret key r such that R=r*G and D=r*A
    * When the recipient's address is a subaddress, the tx pubkey R is defined as R=r*B where B is the recipient's spend pubkey
    */
  signature generate_tx_proof
  (
   const hash &prefix_hash
   , const public_key &R
   , const public_key &A
   , const std::optional<public_key> &B
   , const public_key &D
   , const secret_key &r
   );

}
