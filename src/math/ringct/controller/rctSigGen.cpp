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

#include "rctSigGen.hpp"

#include "math/ringct/functional/curveConstants.hpp"
#include "math/ringct/pseudo_functional/bulletproofs.hpp"

#include "cryptonote/basic/cryptonote_format_utils.h"

#include "tools/common/threadpool.h"
#include "tools/epee/include/logging.hpp"

#include "cryptonote/basic/functional/subaddress.hpp"


#include "config/cryptonote.hpp"

using namespace std;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

namespace rct {

  std::tuple<rct_scalarV, Bulletproof> generate_range_proof
  (
   const std::vector<uint64_t> amounts
   , const std::span<const rct_scalar> sk
   )
  {
    LOG_ERROR_AND_THROW_UNLESS(amounts.size() == sk.size(), "Invalid amounts/sk sizes");

    std::vector<std::pair<uint64_t, rct_scalar>> xs;
    std::transform
      (
       amounts.begin()
       , amounts.end()
       , sk.begin()
       , std::back_inserter(xs)
       , [](const auto& amount, const auto& x) -> std::pair<uint64_t, rct_scalar> {
         return {amount, rct::get_blinding_factor_from_shared_secret_hash(x)};
       }
       );

    const Bulletproof proof = bulletproof_MAKE(xs);
    LOG_ERROR_AND_THROW_UNLESS(proof.V.size() == amounts.size(), "V does not have the expected size");

    rct_scalarV blinding_factors;
    std::transform
      (
       xs.begin()
       , xs.end()
       , std::back_inserter(blinding_factors)
       , [](const auto& x) { return x.second; }
       );

    return {blinding_factors, proof};
  }


  // Generate a CLSAG signature
  // See paper by Goodell et al. (https://eprint.iacr.org/2019/654)
  //
  // The keys are set as follows:
  //   P[l] == p*G
  //   C[l] == z*G
  //   C[i] == C_nonzero[i] - C_offset (for hashing purposes) for all i
  clsag generate_clsag_signature_internal
  (
    const crypto::hash message
    , const rct_pointV P
    , const rct_scalar p
    , const rct_pointV C
    , const rct_scalar z
    , const rct_pointV C_nonzero
    , const rct_point C_offset
    , const size_t idx
    )
  {
    clsag sig;
    size_t n = P.size(); // ring size
    LOG_ERROR_AND_THROW_UNLESS(n == C.size(), "Signing and commitment rct_point vector sizes must match!");
    LOG_ERROR_AND_THROW_UNLESS(n == C_nonzero.size(), "Signing and commitment rct_point vector sizes must match!");
    LOG_ERROR_AND_THROW_UNLESS(idx < n, "Signing index out of range!");

    // mages images
    const rct_point P_hash = hash_to_point_via_field(P[idx]);

    const rct_scalar a = crypto::scalarGen();
    sig.I = P_hash ^ p;
    const rct_point D = P_hash ^ z;

    // Offset key image
    sig.D = D ^ rct::s_inv_eight;

    crypto::dataV mu_P_to_hash = {{}};
    mu_P_to_hash.insert(mu_P_to_hash.end(), P.begin(), P.end());
    mu_P_to_hash.insert(mu_P_to_hash.end(), C_nonzero.begin(), C_nonzero.end());
    mu_P_to_hash.push_back(sig.I);
    mu_P_to_hash.push_back(sig.D);
    mu_P_to_hash.push_back(C_offset);

    crypto::dataV mu_C_to_hash = mu_P_to_hash;

    std::copy_n
      (
        config::HASH_KEY_CLSAG_AGG_0.data()
        , config::HASH_KEY_CLSAG_AGG_0.size()
        , mu_P_to_hash[0].data.begin()
        );

    std::copy_n
      (
        config::HASH_KEY_CLSAG_AGG_1.data()
        , config::HASH_KEY_CLSAG_AGG_1.size()
        , mu_C_to_hash[0].data.begin()
        );


    const rct_scalar mu_P = hash_dataV_to_scalar(mu_P_to_hash);
    const rct_scalar mu_C = hash_dataV_to_scalar(mu_C_to_hash);

    // Initial commitment
    crypto::dataV c_to_hash = {{}};
    std::copy_n
      (
        config::HASH_KEY_CLSAG_ROUND.data()
        , config::HASH_KEY_CLSAG_ROUND.size()
        , c_to_hash[0].data.begin()
        );

    c_to_hash.insert(c_to_hash.end(), P.begin(), P.end());
    c_to_hash.insert(c_to_hash.end(), C_nonzero.begin(), C_nonzero.end());
    c_to_hash.push_back(C_offset);
    c_to_hash.push_back(crypto::h2d(message));
    c_to_hash.push_back(G_(a));
    c_to_hash.push_back(P_hash ^ a);


    rct_scalar c = rct::hash_dataV_to_scalar(c_to_hash);

    size_t i = (idx + 1) % n;
    if (i == 0) {
      sig.c1 = c;
    }

    // Decoy indices
    rct_scalarV s(n);

    while (i != idx) {
      // carried from last round
      const rct_scalar c_p = mu_P * c;
      const rct_scalar c_c = mu_C * c;

      const auto sk = crypto::scalarGen();

      // Compute L
      const rct_point L = addPoints
        (
         std::array
         {
           G_(sk)
           , P[i] ^ c_p
           , C[i] ^ c_c
         }
         );

      // Compute R
      const rct_point A = hash_to_point_via_field(P[i]);
      const rct_point R = addPoints
        (
         std::array
         {
           A ^ sk
           , sig.I ^ c_p
           , D ^ c_c
         }
         );

      s[i] = sk;

      c_to_hash[2*n+3] = L;
      c_to_hash[2*n+4] = R;
      // need to be remembered
      c = rct::hash_dataV_to_scalar(c_to_hash);

      i = (i + 1) % n;
      if (i == 0) {
        sig.c1 = c;
      }
    }

    // Compute final scalar
    s[idx] = a - c * (mu_C * z + mu_P * p);

    sig.s = s;

    return sig;
  }


  clsag generate_clsag_signature
  (
   const crypto::hash message
   , const ct_public_keyV pubs
   , const ct_secret_key inSk
   , const rct_scalar a
   , const rct_point Cout
   , const size_t index
   )
  {
    LOG_ERROR_AND_THROW_IF(pubs.empty(), "Empty pubs");

    rct_pointV P;
    std::transform
      (
        pubs.begin()
        , pubs.end()
        , std::back_inserter(P)
        , [](const auto& x) { return x.dest; }
        );

    rct_pointV C_nonzero;
    std::transform
      (
        pubs.begin()
        , pubs.end()
        , std::back_inserter(C_nonzero)
        , [](const auto& x) { return x.amount_commit; }
        );

    rct_pointV C;
    std::transform
      (
        pubs.begin()
        , pubs.end()
        , std::back_inserter(C)
        , [Cout](const auto& x) { return x.amount_commit - Cout; }
        );

    return generate_clsag_signature_internal
      (message, P, inSk.addr, C, inSk.blinding_factor - a, C_nonzero, Cout, index);
  }


  std::pair<rctData, ct_secret_keyV> generate_ringct
  (
   const crypto::hash message
   , const ct_secret_keyV inSk
   , const rct_pointV destinations
   , const vector<amount_t> inamounts
   , const vector<amount_t> outamounts
   , const amount_t fee
   , const ct_public_keyM mixRing
   , const rct_scalarV tx_output_shared_secret_indexed_hashes
   , const std::vector<size_t> index
   )
  {
    LOG_ERROR_AND_THROW_UNLESS(inamounts.size() > 0, "Empty inamounts");
    LOG_ERROR_AND_THROW_UNLESS(inamounts.size() == inSk.size(), "Different number of inamounts/inSk");
    LOG_ERROR_AND_THROW_UNLESS(outamounts.size() == destinations.size(), "Different number of amounts/destinations");
    LOG_ERROR_AND_THROW_UNLESS(tx_output_shared_secret_indexed_hashes.size() == destinations.size(), "Different number of tx_output_shared_secret_indexed_hashes/destinations");
    LOG_ERROR_AND_THROW_UNLESS(index.size() == inSk.size(), "Different number of index/inSk");
    LOG_ERROR_AND_THROW_UNLESS(mixRing.size() == inSk.size(), "Different number of mixRing/inSk");
    for (size_t n = 0; n < mixRing.size(); ++n) {
      LOG_ERROR_AND_THROW_UNLESS(index[n] < mixRing[n].size(), "Bad index into mixRing");
    }


    const auto [blinding_factors, proof] = generate_range_proof(outamounts, tx_output_shared_secret_indexed_hashes);

    ct_secret_keyV outSk;
    std::transform
      (
       blinding_factors.begin()
       , blinding_factors.end()
       , std::back_inserter(outSk)
       , [](const auto& x) -> ct_secret_key {
         return {{}, x};
       }
       );


    ct_public_keyV outPk;
    std::transform
      (
       destinations.begin()
       , destinations.end()
       , proof.V.begin()
       , std::back_inserter(outPk)
       , [](const auto& x, const auto& y) -> ct_public_key {
         return {x, rct::multP8(y)};
       }
       );


    std::vector<ecdh_encrypted_data> ecdh;
    std::transform
      (
       outamounts.begin(),
       outamounts.end(),
       tx_output_shared_secret_indexed_hashes.begin(),
       std::back_inserter(ecdh),
       [](const auto& x, const auto& y) -> ecdh_encrypted_data {
         return {crypto::d2s(encode_by_ecdh_shared_secret_hash(crypto::int_to_scalar(x), y))};
       }
       );


    rct_scalar sum_blinding_factors = std::accumulate
      (
       outSk.begin()
       , outSk.end()
       , s_zero
       , [](const auto& x, const auto& y) {
         return x + y.blinding_factor;
       }
       );


    // reserve the last one for generating a balanced pseudo sum
    rct_scalarV pseudo_blinding_factors(inamounts.size() - 1);
    std::generate
      (
       pseudo_blinding_factors.begin()
       , pseudo_blinding_factors.end()
       , []() { return crypto::scalarGen(); }
       );

    rct_scalar pseudo_sum_blinding_factors =
      std::accumulate
      (
       pseudo_blinding_factors.begin()
       , pseudo_blinding_factors.end()
       , s_zero
       , std::plus<>()
       );

    rct_pointV pseudo_amount_commits;
    std::transform
      (
       pseudo_blinding_factors.begin()
       , pseudo_blinding_factors.end()
       , inamounts.begin()
       , std::back_inserter(pseudo_amount_commits)
       , [](const auto& x, const auto& y) -> rct_point {
         return commit(x, y);
       }
       );

    const auto pseudo_sum_blinding_factor_difference = sum_blinding_factors - pseudo_sum_blinding_factors;
    pseudo_blinding_factors.push_back(pseudo_sum_blinding_factor_difference);

    pseudo_amount_commits.push_back(commit(pseudo_sum_blinding_factor_difference, inamounts.back()));

    const rctData preRctSig =
      {
        RCTTypeCLSAG
        , message
        , mixRing
        , ecdh
        , outPk
        , fee
        , {
          {toUnsafeBulletproof(proof)}
          , {}
          , pseudo_amount_commits
        }
      };

    const crypto::hash full_message = get_ring_signature_message(preRctSig);
    std::vector<clsag_unsafe> clsags(inamounts.size());
    std::generate
      (
       clsags.begin()
       , clsags.end()
       , [full_message, mixRing, inSk, pseudo_blinding_factors, pseudo_amount_commits, index, i = 0]() mutable {
         const auto clsag = generate_clsag_signature
           (
            full_message
            , mixRing[i]
            , inSk[i]
            , pseudo_blinding_factors[i]
            , pseudo_amount_commits[i]
            , index[i]
            );
         i++;
         return toUnsafeCLSAG(clsag);
       }
       );

    rctData rctData = preRctSig;
    rctData.p.CLSAGs = clsags;

    return {rctData, outSk};
  }

}
