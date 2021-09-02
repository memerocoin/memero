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
    crypto::hash get_mlsag_pre_hash(const rctSig rv)
    {
      LOG_ERROR_AND_THROW_UNLESS(!rv.mixRing.empty(), "Empty mixRing");

      crypto::dataV hashes;
      hashes.push_back(crypto::h2d(rv.message));


      std::stringstream ss;
      binary_archive<true> ba(ss);

      const size_t inputs = rv.mixRing.size();
      const size_t outputs = rv.ecdhInfo.size();


      LOG_ERROR_AND_THROW_UNLESS
        (
         const_cast<rctSig&>(rv).serialize_rctsig_base(ba, inputs, outputs)
         , "Failed to serialize rctSigBase"
         );

      const crypto::hash h = cryptonote::get_blob_hash(ss.str());

      hashes.push_back(h2d(h));

      crypto::dataV kv;
      {
        kv.reserve((6*2+9) * rv.p.bulletproofs.size());
        for (const auto &p: rv.p.bulletproofs)
        {
          // V are not hashed as they're expanded from outPk.mask
          // (and thus hashed as part of rctSigBase above)
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


    bool verRctCLSAGSimpleMayThrow
    (
     const crypto::hash message
     , const clsag sig
     , const ct_public_keyS pubs
     , const rct_point C_offset
     )
    {
        const size_t n = pubs.size();

        // Check data
        LOG_ERROR_AND_RETURN_UNLESS(n >= 1, false, "Empty pubs");
        LOG_ERROR_AND_RETURN_UNLESS(n == sig.s.size(), false, "Signature rct_scalar vector is the wrong size!");
        for (const auto &s: sig.s)
          LOG_ERROR_AND_RETURN_UNLESS(crypto::is_reduced(s), false, "Bad signature scalar!");
        LOG_ERROR_AND_RETURN_UNLESS(crypto::is_reduced(sig.c1), false, "Bad signature commitment!");
        LOG_ERROR_AND_RETURN_IF((sig.I == rct::identity), false, "Bad rct_point image!");

        if (!is_valid_point(C_offset)) {
          LOG_ERROR("C_offset is not a valid point: " << C_offset);
          return false;
        }

        // Prepare key images
        const rct_point D_8 = multP8(sig.D);
        LOG_ERROR_AND_RETURN_IF((D_8 == rct::identity), false, "Bad auxiliary rct_point image!");

        // Aggregation hashes
        crypto::dataV mu_P_to_hash = {zero};
        std::transform
          (
           pubs.begin()
           , pubs.end()
           , std::back_inserter(mu_P_to_hash)
           , [](const auto& x) { return x.dest; }
           );

        std::transform
          (
           pubs.begin()
           , pubs.end()
           , std::back_inserter(mu_P_to_hash)
           , [](const auto& x) { return x.commit_of_amount; }
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
        crypto::dataV c_to_hash = {zero}; // domain, P, C, C_offset, message, L, R
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
           , [](const auto& x) { return x.dest; }
           );

        std::transform
          (
           pubs.begin()
           , pubs.end()
           , std::back_inserter(c_to_hash)
           , [](const auto& x) { return x.commit_of_amount; }
           );

        c_to_hash.push_back(C_offset);
        c_to_hash.push_back(crypto::h2d(message));
        c_to_hash.push_back({}); // reserve for L
        c_to_hash.push_back({}); // reserve for R


        rct_scalar c = rct_reduce(sig.c1);
        size_t i = 0;

        while (i < n) {
            const rct_scalar c_p = mu_P * c;
            const rct_scalar c_c = mu_C * c;

            const rct_point mask = pubs[i].commit_of_amount;
            if (!is_valid_point(mask)) {
              LOG_ERROR("pubs[" << i << "].commit_of_amount.data is not a valid point: " << mask);
              return false;
            }

            const rct_point C = mask - C_offset;

            // Compute L
            const rct_point L = addPoints
              (
               std::array
               {
                 G_(rct_reduce(sig.s[i]))
                 , pubs[i].dest ^ c_p
                 , C ^ c_c
               }
               );

            // Compute R
            const rct_point k = hash_to_point_via_field(pubs[i].dest);

            const rct_point R = addPoints
              (
               std::array
               {
                 k ^ sig.s[i]
                 , sig.I ^ c_p
                 , D_8 ^ c_c
               }
               );

            c_to_hash[2*n+3] = L;
            c_to_hash[2*n+4] = R;

            c = hash_dataV_to_scalar(c_to_hash);
            LOG_ERROR_AND_RETURN_IF((c == rct::s_zero), false, "Bad signature hash");

            i++;
        }

        return s2s(c - sig.c1) == s_zero;
    }

    bool verRctCLSAGSimple
    (
     const crypto::hash message
     , const clsag sig
     , const ct_public_keyS pubs
     , const rct_point C_offset
     )
    {
      try {
        return verRctCLSAGSimpleMayThrow(message, sig, pubs, C_offset);
      }
      catch (...) { return false; }
    }


    bool verRctSemanticsSimpleMayThrow(const std::span<const rctSig> rvv)
    {
        for (const rctSig& rv: rvv)
        {
          LOG_ERROR_AND_RETURN_UNLESS
            (
             rv.type == RCTTypeCLSAG
             , false
             , "verRctSemanticsSimple called on non simple rctSig"
             );

          LOG_ERROR_AND_RETURN_UNLESS
            (
             rv.outPk.size() == n_bulletproof_amounts(rv.p.bulletproofs)
             , false
             , "Mismatched sizes of outPk and bulletproofs"
             );

          LOG_ERROR_AND_RETURN_UNLESS
            (
             rv.p.pseudoOuts.size() == rv.p.CLSAGs.size()
             , false
             , "Mismatched sizes of rv.p.pseudoOuts and rv.p.CLSAGs"
             );

          LOG_ERROR_AND_RETURN_UNLESS
            (
             rv.pseudoOuts.empty()
             , false
             , "rv.pseudoOuts is not empty"
             );

          LOG_ERROR_AND_RETURN_UNLESS
            (
             rv.outPk.size() == rv.ecdhInfo.size()
             , false
             , "Mismatched sizes of outPk and rv.ecdhInfo"
             );
        }

        return std::transform_reduce
          (
           rvv.begin()
           , rvv.end()
           , true
           , std::logical_and<>()
           , [](const rctSig& rv) {
             const rct_pointV &pseudoOuts = rv.p.pseudoOuts;

             rct::rct_pointV masks;
             std::transform
               (
                rv.outPk.begin()
                , rv.outPk.end()
                , std::back_inserter(masks)
                , [](const auto& x) {
                  return x.commit_of_amount;
                }
                );

             const rct_point txnFeeKey = H_(int_to_scalar(rv.txnFee));
             const rct_point sumOutpks = addPoints(masks) + txnFeeKey;
             const rct_point sumPseudoOuts = addPoints(pseudoOuts);

             //check pseudoOuts vs Outs..
             if (sumPseudoOuts != sumOutpks) {
               LOG_PRINT_L1("Sum check failed");
               return false;
             }

             return bulletproof_VERIFY(rv.p.bulletproofs);
           }
           );
    }

    bool verRctSemanticsSimple(const std::span<const rctSig> rvv) {
      try {
        return verRctSemanticsSimpleMayThrow(rvv);
      }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (const std::exception &e)
        {
          LOG_PRINT_L1("Error in verRctSemanticsSimple: " << e.what());
          return false;
        }
      catch (...)
        {
          LOG_PRINT_L1("Error in verRctSemanticsSimple, but not an actual exception");
          return false;
        }
    }

    bool verRctSemanticsSimple(const rctSig rv)
    {
      return verRctSemanticsSimple(std::vector<rctSig>{rv});
    }

    //ver RingCT simple
    //assumes only post-rct style inputs (at least for max anonymity)
    bool verRctNonSemanticsSimpleMayThrow(const rctSig rv)
    {
        LOG_ERROR_AND_RETURN_UNLESS
          (
           rv.type == RCTTypeCLSAG
           , false
           , "verRctNonSemanticsSimple called on non simple rctSig"
           );

        // semantics check is early, and mixRing/MGs aren't resolved yet
        LOG_ERROR_AND_RETURN_UNLESS
          (
           rv.p.pseudoOuts.size() == rv.mixRing.size()
           , false
           , "Mismatched sizes of rv.p.pseudoOuts and mixRing"
           );

        const size_t threads = std::max(rv.outPk.size(), rv.mixRing.size());

        std::deque<bool> results(threads);
        tools::threadpool& tpool = tools::threadpool::getInstance();
        tools::threadpool::waiter waiter(tpool);

        const rct_pointV &pseudoOuts = rv.p.pseudoOuts;

        const crypto::hash message = get_mlsag_pre_hash(rv);

        results.clear();
        results.resize(rv.mixRing.size());
        for (size_t i = 0 ; i < rv.mixRing.size() ; i++) {
          tpool.submit(&waiter, [&, i] {
            results[i] = verRctCLSAGSimple
              (message, rv.p.CLSAGs[i], rv.mixRing[i], pseudoOuts[i]);
          });
        }
        if (!waiter.wait())
          return false;

        for (size_t i = 0; i < results.size(); ++i) {
          if (!results[i]) {
            LOG_PRINT_L1("verRctCLSAGSimple failed for input " << i);
            return false;
          }
        }

        return true;
    }

    bool verRctNonSemanticsSimple(const rctSig rv) {
      try {
        return verRctNonSemanticsSimpleMayThrow(rv);
      }

      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (const std::exception &e)
      {
        LOG_PRINT_L1("Error in verRctNonSemanticsSimple: " << e.what());
        return false;
      }
      catch (...)
      {
        LOG_PRINT_L1("Error in verRctNonSemanticsSimple, but not an actual exception");
        return false;
      }
    }

    std::pair<amount_t, rct_scalar> decodeRctSimple(const rctSig rv, const rct_scalar ecdh_shared_secret, const size_t i)
    {
        LOG_ERROR_AND_THROW_UNLESS(rv.type == RCTTypeCLSAG, "decodeRct called on non simple rctSig");
        LOG_ERROR_AND_THROW_UNLESS(i < rv.ecdhInfo.size(), "Bad index");
        LOG_ERROR_AND_THROW_UNLESS(rv.outPk.size() == rv.ecdhInfo.size(), "Mismatched sizes of rv.outPk and rv.ecdhInfo");

        const rct_scalar blinding_factor = rct::get_blinding_factor_from_ecdh_shared_secret(ecdh_shared_secret);
        LOG_ERROR_AND_THROW_UNLESS(crypto::is_reduced(blinding_factor), "warning, bad ECDH blinding_factor");

        const crypto::ec_scalar_unnormalized amount_unnormalized =
          crypto::d2s(rct::decode_by_ecdh_shared_secret(rv.ecdhInfo[i].masked_amount, ecdh_shared_secret));
        LOG_ERROR_AND_THROW_UNLESS(crypto::is_reduced(amount_unnormalized), "warning, bad ECDH amount");

        const rct_point C = rv.outPk[i].commit_of_amount;

        const auto amount = rct::s2s(crypto::reduce(amount_unnormalized));

        if (C != addMultG_H(blinding_factor, amount)) {
            LOG_ERROR_AND_THROW("warning, amount decoded incorrectly, will be unable to spend");
        }
        return {scalar_to_int(amount), blinding_factor};
    }
}
