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

#include "ringCT.hpp"

#include "clsag.hpp"

#include "tools/common/threadpool.h"
#include "tools/epee/include/logging.hpp"

#include "math/ringct/functional/curveConstants.hpp"
#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/pseudo_functional/bulletproofs.hpp"

#include "cryptonote/basic/functional/format_utils.hpp"

#include "consensus/consensus.hpp"

#include "config/cryptonote.hpp"


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

namespace rct {

  std::optional<crypto::hash> get_ring_signature_message(const rctData rv)
  {
    LOG_ERROR_AND_RETURN_UNLESS(!rv.decoys.empty(), {}, "Empty decoys");

    crypto::dataV hashes;
    hashes.push_back(crypto::h2d(rv.message));


    std::stringstream ss;
    binary_archive<true> ba(ss);

    const size_t inputs = rv.decoys.size();
    const size_t outputs = rv.ecdh_encrypted_data.size();


    LOG_ERROR_AND_RETURN_UNLESS
      (
        const_cast<rctData&>(rv).serialize_rctsig_base(ba, inputs, outputs)
        , {}
        , "Failed to serialize rctDataBasic"
        );

    const crypto::hash h = cryptonote::get_blob_hash(ss.str());

    hashes.push_back(h2d(h));

    crypto::dataV kv;
    {
      kv.reserve((6*2+9) * rv.p.bulletproofs.size());
      for (const auto &p: rv.p.bulletproofs)
      {
        // V are not hashed as they're expanded from output_commits.mask
        // (and thus hashed as part of rctDataBasic above)
        kv.push_back(p.A);
        kv.push_back(p.S);
        kv.push_back(p.T1);
        kv.push_back(p.T2);
        kv.push_back(p.taux);
        kv.push_back(p.mu);
        for (const auto &l: p.L)
          kv.push_back(l);
        for (const auto &r: p.R)
          kv.push_back(r);
        kv.push_back(p.a);
        kv.push_back(p.b);
        kv.push_back(p.t);
      }
    }

    hashes.push_back(h2d(hash_dataV(kv)));

    return hash_dataV(hashes);
  }

  bool verify_unsafe_clsag_signature
  (
   const crypto::hash message
   , const clsag_unsafe sig
   , const output_public_dataS decoys
   , const rct_point pseudo_input_commit
   )
  {
    const auto maybeClsag = maybeSafeCLSAG(sig);
    LOG_ERROR_AND_RETURN_UNLESS
      (
       maybeClsag
       , false
       , "invalid clsag signature"
       );

    return consensus::rule_4_tx_input_should_be_from_a_ring(message, *maybeClsag, decoys, pseudo_input_commit);
  }

  bool verify_tx_balance(const rctData rv) {
    LOG_ERROR_AND_RETURN_UNLESS
      (
       rv.type == RCTTypeCLSAG
       , false
       , "verify_tx_balance called on non rct tx"
       );

    rct::rct_pointV output_commits;

    std::transform
      (
       rv.output_commits.begin()
       , rv.output_commits.end()
       , std::back_inserter(output_commits)
       , [](const auto& x) {
         return x.commit;
       }
       );

    return consensus::rule_3_tx_should_be_balanced(rv.p.pseudo_input_commits, output_commits, rv.fee);
  }

  bool verify_range_proof(const rctData rv)
  {
    LOG_ERROR_AND_RETURN_UNLESS
      (
        rv.type == RCTTypeCLSAG
        , false
        , "verify_range_proof called on non rct tx"
        );

    LOG_ERROR_AND_RETURN_UNLESS
      (
        rv.p.bulletproofs.size() == 1
        , false
        , "More than one proofs"
        );

    LOG_ERROR_AND_RETURN_UNLESS
      (
       is_bulletproof_structure_valid(rv.output_commits.size(), rv.p.bulletproofs.front())
        , false
        , "Mismatched sizes of output_commits and bulletproofs"
        );

    LOG_ERROR_AND_RETURN_UNLESS
      (
        rv.p.pseudo_input_commits.size() == rv.p.CLSAGs.size()
        , false
        , "Mismatched sizes of rv.p.pseudo_input_commits and rv.p.CLSAGs"
        );

    LOG_ERROR_AND_RETURN_UNLESS
      (
        rv.output_commits.size() == rv.ecdh_encrypted_data.size()
        , false
        , "Mismatched sizes of output_commits and rv.ecdh_encrypted_data"
        );

    const auto maybeProof = rct::maybeSafeBulletproof(rv.p.bulletproofs.front());
    LOG_ERROR_AND_RETURN_UNLESS(maybeProof, false, "Bad proof");

    rct::rct_pointV output_commits;

    std::transform
      (
       rv.output_commits.begin()
       , rv.output_commits.end()
       , std::back_inserter(output_commits)
       , [](const auto& x) {
         return x.commit;
       }
       );

    return consensus::rule_2_tx_output_amounts_should_not_overflow_amount_type(output_commits, *maybeProof);
  }

  //ver RingCT simple
  //assumes only post-rct style inputs (at least for max anonymity)
  bool verify_clsag_signatures(const rctData rv)
  {
    LOG_ERROR_AND_RETURN_UNLESS
      (
        rv.type == RCTTypeCLSAG
        , false
        , "verify_clsag_signatures called on non simple rctData"
        );

    // semantics check is early, and decoys/MGs aren't resolved yet
    LOG_ERROR_AND_RETURN_UNLESS
      (
        rv.p.pseudo_input_commits.size() == rv.decoys.size()
        , false
        , "Mismatched sizes of rv.p.pseudo_input_commits and decoys"
        );

    const size_t threads = std::max(rv.output_commits.size(), rv.decoys.size());

    std::deque<bool> results(threads);
    tools::threadpool& tpool = tools::threadpool::getInstance();
    tools::threadpool::waiter waiter(tpool);

    const rct_pointV &pseudo_input_commits = rv.p.pseudo_input_commits;

    const auto maybeMessage = get_ring_signature_message(rv);
    if (!maybeMessage) return false;

    const crypto::hash message = *maybeMessage;

    results.clear();
    results.resize(rv.decoys.size());
    for (size_t i = 0 ; i < rv.decoys.size() ; i++) {
      tpool.submit(&waiter, [&, i] {
        results[i] = verify_unsafe_clsag_signature
          (message, rv.p.CLSAGs[i], rv.decoys[i], pseudo_input_commits[i]);
      });
    }
    if (!waiter.wait())
      return false;

    for (size_t i = 0; i < results.size(); ++i) {
      if (!results[i]) {
        LOG_PRINT_L1("verify_clsag_signature failed for input " << i);
        return false;
      }
    }

    return true;
  }

  std::pair<amount_t, rct_scalar> decode_ringct_commitment
  (
    const rctData rv
    , const rct_scalar ecdh_shared_secret_hashed_by_index
    , const size_t output_index
    )
  {
    LOG_ERROR_AND_THROW_UNLESS(rv.type == RCTTypeCLSAG, "decodeRct called on non simple rctData");
    LOG_ERROR_AND_THROW_UNLESS(output_index < rv.ecdh_encrypted_data.size(), "Bad index");
    LOG_ERROR_AND_THROW_UNLESS
      (
       rv.output_commits.size() == rv.ecdh_encrypted_data.size()
       , "Mismatched sizes of rv.output_commits and rv.ecdh_encrypted_data"
       );

    const rct_scalar blinding_factor =
      rct::get_blinding_factor_from_hashed_shared_secret(ecdh_shared_secret_hashed_by_index);

    const uint64_t amount = rct::decode_amount_by_hashed_ecdh_shared_secret
      (rv.ecdh_encrypted_data[output_index].masked_amount, ecdh_shared_secret_hashed_by_index);

    const rct_point C = rv.output_commits[output_index].commit;

    if (C != commit(amount, blinding_factor)) {
      LOG_ERROR_AND_THROW("warning, amount decoded incorrectly, will be unable to spend");
    }

    return {amount, blinding_factor};
  }
}
