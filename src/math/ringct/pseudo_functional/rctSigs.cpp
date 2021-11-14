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

#include "rctSigs.hpp"

#include "math/ringct/functional/curveConstants.hpp"

#include "math/ringct/pseudo_functional/bulletproofs.hpp"

#include "cryptonote/basic/cryptonote_format_utils.h"

#include "tools/common/threadpool.h"
#include "tools/epee/include/logging.hpp"


#include "config/cryptonote.hpp"

using namespace std;

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
    const size_t outputs = rv.ecdh.size();


    LOG_ERROR_AND_RETURN_UNLESS
      (
        const_cast<rctData&>(rv).serialize_rctsig_base(ba, inputs, outputs)
        , {}
        , "Failed to serialize rctDataEssential"
        );

    const crypto::hash h = cryptonote::get_blob_hash(ss.str());

    hashes.push_back(h2d(h));

    crypto::dataV kv;
    {
      kv.reserve((6*2+9) * rv.p.bulletproofs.size());
      for (const auto &p: rv.p.bulletproofs)
      {
        // V are not hashed as they're expanded from outPk.mask
        // (and thus hashed as part of rctDataEssential above)
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


  bool verify_clsag_signature
  (
    const crypto::hash message
    , const clsag sig
    , const output_public_dataS pubs
    , const rct_point C_offset
    )
  {
    const size_t n = pubs.size();

    // Check data
    LOG_ERROR_AND_RETURN_UNLESS(n >= 1, false, "Empty pubs");
    LOG_ERROR_AND_RETURN_UNLESS(n == sig.s.size(), false, "Signature rct_scalar vector is the wrong size!");

    if (!is_safe_point(C_offset)) {
      LOG_ERROR("C_offset is not a valid point: " << C_offset);
      return false;
    }

    // Aggregation hashes
    crypto::dataV mu_P_to_hash = {{}};
    std::transform
      (
        pubs.begin()
        , pubs.end()
        , std::back_inserter(mu_P_to_hash)
        , [](const auto& x) { return x.output_spend_pk; }
        );

    std::transform
      (
        pubs.begin()
        , pubs.end()
        , std::back_inserter(mu_P_to_hash)
        , [](const auto& x) { return x.amount_commit; }
        );

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

    // Set up round hash
    crypto::dataV c_to_hash = {{}}; // domain, P, C, C_offset, message, L, R
    std::copy_n
      (
        config::HASH_KEY_CLSAG_ROUND.data()
        , config::HASH_KEY_CLSAG_ROUND.size()
        , c_to_hash[0].data.begin()
        );

    std::transform
      (
        pubs.begin()
        , pubs.end()
        , std::back_inserter(c_to_hash)
        , [](const auto& x) { return x.output_spend_pk; }
        );

    std::transform
      (
        pubs.begin()
        , pubs.end()
        , std::back_inserter(c_to_hash)
        , [](const auto& x) { return x.amount_commit; }
        );

    c_to_hash.push_back(C_offset);
    c_to_hash.push_back(crypto::h2d(message));
    c_to_hash.push_back({}); // reserve for L
    c_to_hash.push_back({}); // reserve for R


    const rct_scalar c1 = sig.c1;

    rct_scalar c = c1;
    size_t i = 0;

    while (i < n) {
      const rct_scalar c_p = mu_P * c;
      const rct_scalar c_c = mu_C * c;

      const rct_point mask = pubs[i].amount_commit;
      if (!is_safe_point(mask)) {
        LOG_ERROR("pubs[" << i << "].amount_commit.data is not a valid point: " << mask);
        return false;
      }

      const rct_point C = mask - C_offset;

      // Compute L
      const rct_point L = sum
        (
          std::array
          {
            G_(sig.s[i])
            , pubs[i].output_spend_pk ^ c_p
            , C ^ c_c
          }
          );

      // Compute R
      const rct_point k = hash_to_point_via_field(pubs[i].output_spend_pk);

      const rct_point R = sum
        (
          std::array
          {
            k ^ sig.s[i]
            , sig.I ^ c_p
            , sig.D ^ (c_c * s_eight)
          }
          );

      c_to_hash[2*n+3] = L;
      c_to_hash[2*n+4] = R;

      c = hash_dataV_to_scalar(c_to_hash);
      LOG_ERROR_AND_RETURN_IF((c == rct::s_zero), false, "Bad signature hash");

      i++;
    }

    return c == c1;
  }

  bool verify_unsafe_clsag_signature
  (
   const crypto::hash message
   , const clsag_unsafe sig
   , const output_public_dataS pubs
   , const rct_point C_offset
   )
  {
    const auto maybeClsag = maybeSafeCLSAG(sig);
    LOG_ERROR_AND_RETURN_UNLESS
      (
       maybeClsag
       , false
       , "invalid clsag signature"
       );

    return verify_clsag_signature(message, *maybeClsag, pubs, C_offset);
  }

  bool verify_tx_balance(const rctData rv) {
    LOG_ERROR_AND_RETURN_UNLESS
      (
       rv.type == RCTTypeCLSAG
       , false
       , "verify_tx_balance called on non rct tx"
       );

    rct::rct_pointV outputCommits;

    std::transform
      (
       rv.outPk.begin()
       , rv.outPk.end()
       , std::back_inserter(outputCommits)
       , [](const auto& x) {
         return x.amount_commit;
       }
       );

    const rct_point feeCommit = H_(crypto::int_to_scalar(rv.fee));
    const rct_point sumOutputCommits = sum(outputCommits) + feeCommit;
    const rct_point sumInputCommits = sum(rv.p.pseudo_amount_commits);

    //check pseudo_amount_commits vs Outs..
    return sumInputCommits == sumOutputCommits;
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
        rv.outPk.size() == n_bulletproof_amounts(rv.p.bulletproofs.front())
        , false
        , "Mismatched sizes of outPk and bulletproofs"
        );

    LOG_ERROR_AND_RETURN_UNLESS
      (
        rv.p.pseudo_amount_commits.size() == rv.p.CLSAGs.size()
        , false
        , "Mismatched sizes of rv.p.pseudo_amount_commits and rv.p.CLSAGs"
        );

    LOG_ERROR_AND_RETURN_UNLESS
      (
        rv.outPk.size() == rv.ecdh.size()
        , false
        , "Mismatched sizes of outPk and rv.ecdh"
        );

    const auto maybeProof = rct::maybeSafeBulletproof(rv.p.bulletproofs.front());
    LOG_ERROR_AND_RETURN_UNLESS(maybeProof, false, "Bad proof");
    const Bulletproof proof = *maybeProof;

    return bulletproof_VERIFY(proof);
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
        rv.p.pseudo_amount_commits.size() == rv.decoys.size()
        , false
        , "Mismatched sizes of rv.p.pseudo_amount_commits and decoys"
        );

    const size_t threads = std::max(rv.outPk.size(), rv.decoys.size());

    std::deque<bool> results(threads);
    tools::threadpool& tpool = tools::threadpool::getInstance();
    tools::threadpool::waiter waiter(tpool);

    const rct_pointV &pseudo_amount_commits = rv.p.pseudo_amount_commits;

    const auto maybeMessage = get_ring_signature_message(rv);
    if (!maybeMessage) return false;

    const crypto::hash message = *maybeMessage;

    results.clear();
    results.resize(rv.decoys.size());
    for (size_t i = 0 ; i < rv.decoys.size() ; i++) {
      tpool.submit(&waiter, [&, i] {
        results[i] = verify_unsafe_clsag_signature
          (message, rv.p.CLSAGs[i], rv.decoys[i], pseudo_amount_commits[i]);
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
    , const rct_scalar ecdh_shared_secret
    , const size_t i
    )
  {
    LOG_ERROR_AND_THROW_UNLESS(rv.type == RCTTypeCLSAG, "decodeRct called on non simple rctData");
    LOG_ERROR_AND_THROW_UNLESS(i < rv.ecdh.size(), "Bad index");
    LOG_ERROR_AND_THROW_UNLESS(rv.outPk.size() == rv.ecdh.size(), "Mismatched sizes of rv.outPk and rv.ecdh");

    const rct_scalar blinding_factor = rct::get_blinding_factor_from_hashed_shared_secret(ecdh_shared_secret);
    LOG_ERROR_AND_THROW_UNLESS(crypto::is_reduced(blinding_factor), "warning, bad ECDH blinding_factor");

    const uint64_t amount = rct::decode_amount_by_ecdh_shared_secret(rv.ecdh[i].masked_amount, ecdh_shared_secret);

    const rct_point C = rv.outPk[i].amount_commit;

    if (C != commit(amount, blinding_factor)) {
      LOG_ERROR_AND_THROW("warning, amount decoded incorrectly, will be unable to spend");
    }

    return {amount, blinding_factor};
  }
}
