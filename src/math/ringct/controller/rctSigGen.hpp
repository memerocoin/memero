// Copyright (c) 2021, The Lolnero Project
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

#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/pseudo_functional/rctSigs.hpp"

namespace rct {

  clsag_safe generate_clsag_signature
  (
   const crypto::hash message
   , const ct_public_keyV pubs
   , const ct_secret_key inSk
   , const rct_scalar a
   , const rct_point Cout
   , const size_t index
   );


  //RingCT protocol
  //genRct:
  //   creates an rctData with all data necessary to verify the rangeProofs and that the signer owns one of the
  //   columns that are claimed as inputs, and that the sum of inputs  = sum of outputs.
  //   Also contains masked "amount" and "mask" so the receiver can see how much they received
  //verRct:
  //   verifies that all signatures (rangeProogs, MG sig, sum inputs = outputs) are correct
  //decodeRct: (c.f. https://eprint.iacr.org/2015/1098 section 5.1.1)
  //   uses the attached ecdh info to find the amounts represented by each output commitment
  //   must know the destination private key to find the correct amount, else will return a random number

  std::pair<rctData, ct_secret_keyV> generate_ringct
  (
   const crypto::hash message
   , const ct_secret_keyV inSk
   , const rct_pointV destinations
   , const std::vector<amount_t> inamounts
   , const std::vector<amount_t> outamounts
   , const amount_t fee
   , const ct_public_keyM mixRing
   , const rct_scalarV tx_output_shared_secret_indexed_hashes
   , const std::vector<size_t> index
   );
}

