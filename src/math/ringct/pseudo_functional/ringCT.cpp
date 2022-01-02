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

#include "math/consensus/consensus.hpp"

#include "config/cryptonote.hpp"





namespace rct {

  std::optional<crypto::hash> get_ring_signature_message(const rctDataSizeChecked rv)
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
        const_cast<rctDataSizeChecked&>(rv).serialize_rctsig_base(ba, inputs, outputs)
        , {}
        , "Failed to serialize rctDataBasic"
        );

    const crypto::hash h = cryptonote::get_blob_hash(ss.str());

    hashes.push_back(h2d(h));

    const auto& p = rv.bulletproof;

    crypto::dataV kv;

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

    hashes.push_back(h2d(hash_dataV(kv)));

    return hash_dataV(hashes);
  }

  bool verify_unsafe_clsag_signature
  (
   const crypto::hash message
   , const clsag_unsafe sig
   , const output_public_dataS decoys
   , const crypto::ec_point pseudo_input_commit
   )
  {
    const auto maybeClsag = consensus::rule_10_ring_signature_should_not_contain_invalid_data(sig);
    LOG_ERROR_AND_RETURN_UNLESS
      (
       maybeClsag
       , false
       , "invalid clsag signature"
       );

    return consensus::rule_4_ringct_input_should_be_from_a_key(message, *maybeClsag, decoys, pseudo_input_commit);
  }

  bool verify_ringct_balance(const rctDataSizeChecked rv) {
    rct::pointV output_commits;

    std::transform
      (
       rv.output_commits.begin()
       , rv.output_commits.end()
       , std::back_inserter(output_commits)
       , [](const auto& x) {
         return x.commit;
       }
       );

    return consensus::rule_3_ringct_should_be_balanced(rv.pseudo_input_commits, output_commits, rv.fee);
  }

  bool verify_range_proof(const rctDataSizeChecked rv)
  {
    // const auto maybe_size_checked_rct_data = maybeSizeCheckedRctData(rct_data_unchecked);
    // LOG_ERROR_AND_RETURN_UNLESS(maybe_size_checked_rct_data, false, "Invalid rct data layout");

    // const auto rv = *maybe_size_checked_rct_data;

    const auto maybeProof =
      consensus::rule_9_range_proof_should_not_contain_invalid_data(rv.bulletproof);

    LOG_ERROR_AND_RETURN_UNLESS(maybeProof, false, "Bad proof");

    rct::pointV output_commits;

    std::transform
      (
       rv.output_commits.begin()
       , rv.output_commits.end()
       , std::back_inserter(output_commits)
       , [](const auto& x) {
         return x.commit;
       }
       );

    return consensus::rule_2_ringct_output_amounts_should_not_overflow_amount_type(output_commits, *maybeProof);
  }

  //ver RingCT simple
  //assumes only post-rct style inputs (at least for max anonymity)
  bool verify_clsag_signatures(const rctDataSizeChecked rv)
  {
    // semantics check is early, and decoys/MGs aren't resolved yet
    LOG_ERROR_AND_RETURN_UNLESS
      (
        rv.pseudo_input_commits.size() == rv.decoys.size()
        , false
        , "Mismatched sizes of rv.p.pseudo_input_commits and decoys"
        );

    const size_t threads = std::max(rv.output_commits.size(), rv.decoys.size());

    std::deque<bool> results(threads);
    tools::threadpool& tpool = tools::threadpool::getInstance();
    tools::threadpool::waiter waiter(tpool);

    const pointV &pseudo_input_commits = rv.pseudo_input_commits;

    const auto maybeMessage = get_ring_signature_message(rv);
    if (!maybeMessage) return false;

    const crypto::hash message = *maybeMessage;

    results.clear();
    results.resize(rv.decoys.size());
    for (size_t i = 0 ; i < rv.decoys.size() ; i++) {
      tpool.submit(&waiter, [&, i] {
        results[i] = verify_unsafe_clsag_signature
          (message, rv.CLSAGs[i], rv.decoys[i], pseudo_input_commits[i]);
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

  bool verify_ringct(const rctDataSizeChecked rv) {
    return verify_range_proof(rv) && verify_ringct_balance(rv) && verify_clsag_signatures(rv);
  }

  std::pair<amount_t, rct_scalar> decode_ringct_commitment
  (
    const rctDataSizeChecked rv
    , const rct_scalar ecdh_shared_secret_hashed_by_index
    , const size_t output_index
    )
  {
    LOG_ERROR_AND_THROW_UNLESS(output_index < rv.ecdh_encrypted_data.size(), "Bad index");

    const rct_scalar blinding_factor =
      rct::get_blinding_factor_from_hashed_shared_secret(ecdh_shared_secret_hashed_by_index);

    const uint64_t amount = rct::decode_amount_by_hashed_ecdh_shared_secret
      (rv.ecdh_encrypted_data[output_index].masked_amount, ecdh_shared_secret_hashed_by_index);

    const crypto::ec_point C = rv.output_commits[output_index].commit;

    if (C != commit(amount, blinding_factor)) {
      LOG_ERROR_AND_THROW("warning, amount decoded incorrectly, will be unable to spend");
    }

    return {amount, blinding_factor};
  }
}
