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
#include "curveConstants.hpp"
#include "bulletproofs.hpp"

#include "cryptonote/basic/cryptonote_format_utils.h"

#include "tools/common/threadpool.h"
#include "tools/epee/include/logging.hpp"


#include "config/cryptonote.hpp"

using namespace std;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

namespace rct {
    Bulletproof proveRangeBulletproof
    (
     keyV& C
     , scalarV& masks
     , const std::vector<uint64_t> amounts
     , const std::span<const key> sk)
    {
        hw::device& hwdev = hw::get_device("default");
        LOG_ERROR_AND_THROW_UNLESS(amounts.size() == sk.size(), "Invalid amounts/sk sizes");
        masks.resize(amounts.size());
        for (size_t i = 0; i < masks.size(); ++i)
              masks[i] = hwdev.genCommitmentMask(sk[i]);
        Bulletproof proof = bulletproof_MAKE(amounts, masks);
        LOG_ERROR_AND_THROW_UNLESS(proof.V.size() == amounts.size(), "V does not have the expected size");
        C = proof.V;
        return proof;
    }

    bool verBulletproof(const Bulletproof proof)
    {
      try { return bulletproof_VERIFY(proof); }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (...) { return false; }
    }

    bool verBulletproof(const std::span<Bulletproof> proofs)
    {
      try { return bulletproof_VERIFY(proofs); }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (...) { return false; }
    }

    // Generate a CLSAG signature
    // See paper by Goodell et al. (https://eprint.iacr.org/2019/654)
    //
    // The keys are set as follows:
    //   P[l] == p*G
    //   C[l] == z*G
    //   C[i] == C_nonzero[i] - C_offset (for hashing purposes) for all i
    clsag CLSAG_Gen
    (
     const key message
     , const keyV P
     , const scalar p
     , const keyV C
     , const scalar z
     , const keyV C_nonzero
     , const key C_offset
     , const unsigned int l
     ) {
        hw::device& hwdev = hw::get_device("default");
        clsag sig;
        size_t n = P.size(); // ring size
        LOG_ERROR_AND_THROW_UNLESS(n == C.size(), "Signing and commitment key vector sizes must match!");
        LOG_ERROR_AND_THROW_UNLESS(n == C_nonzero.size(), "Signing and commitment key vector sizes must match!");
        LOG_ERROR_AND_THROW_UNLESS(l < n, "Signing index out of range!");

        // Key images
        key H = hash_to_key_via_f2(P[l]);

        key D;

        // Initial values
        scalar a;
        key aG;
        key aH;

        {
          hwdev.clsag_prepare(p,z,sig.I,D,H,a,aG,aH);
        }

        // Offset key image
        sig.D = scalarmultKey(D, rct::s_inv_eight);

        // Aggregation hashes
        keyV mu_P_to_hash(2*n+4); // domain, I, D, P, C, C_offset
        keyV mu_C_to_hash(2*n+4); // domain, I, D, P, C, C_offset
        sc_0(mu_P_to_hash[0].data);
        memcpy(mu_P_to_hash[0].data,config::HASH_KEY_CLSAG_AGG_0,sizeof(config::HASH_KEY_CLSAG_AGG_0)-1);
        sc_0(mu_C_to_hash[0].data);
        memcpy(mu_C_to_hash[0].data,config::HASH_KEY_CLSAG_AGG_1,sizeof(config::HASH_KEY_CLSAG_AGG_1)-1);
        for (size_t i = 1; i < n+1; ++i) {
            mu_P_to_hash[i] = P[i-1];
            mu_C_to_hash[i] = P[i-1];
        }
        for (size_t i = n+1; i < 2*n+1; ++i) {
            mu_P_to_hash[i] = C_nonzero[i-n-1];
            mu_C_to_hash[i] = C_nonzero[i-n-1];
        }
        mu_P_to_hash[2*n+1] = sig.I;
        mu_P_to_hash[2*n+2] = sig.D;
        mu_P_to_hash[2*n+3] = C_offset;
        mu_C_to_hash[2*n+1] = sig.I;
        mu_C_to_hash[2*n+2] = sig.D;
        mu_C_to_hash[2*n+3] = C_offset;
        scalar mu_P, mu_C;
        mu_P = hash_keys_to_scalar(mu_P_to_hash);
        mu_C = hash_keys_to_scalar(mu_C_to_hash);

        // Initial commitment
        keyV c_to_hash(2*n+5); // domain, P, C, C_offset, message, aG, aH
        scalar c;
        sc_0(c_to_hash[0].data);
        memcpy(c_to_hash[0].data,config::HASH_KEY_CLSAG_ROUND,sizeof(config::HASH_KEY_CLSAG_ROUND)-1);
        for (size_t i = 1; i < n+1; ++i)
        {
            c_to_hash[i] = P[i-1];
            c_to_hash[i+n] = C_nonzero[i-1];
        }
        c_to_hash[2*n+1] = C_offset;
        c_to_hash[2*n+2] = message;

        {
            c_to_hash[2*n+3] = aG;
            c_to_hash[2*n+4] = aH;
        }
        hwdev.clsag_hash(c_to_hash,c);

        size_t i;
        i = (l + 1) % n;
        if (i == 0)
            sig.c1 = c;

        // Decoy indices
        sig.s = scalarV(n);
        scalar c_new;
        key L;
        key R;
        scalar c_p; // = c[i]*mu_P
        scalar c_c; // = c[i]*mu_C

        while (i != l) {
            sig.s[i] = skGen();
            sc_0(c_new.data);
            c_p = mu_P * c;
            c_c = mu_C * c;

            // Compute L
            L = addKeys_aGbBcC
              (
               sig.s[i]
               , c_p, P[i]
               , c_c, C[i]
               );


            // Compute R
            const key A = hash_to_key_via_f2(P[i]);
            R = addKeys_aAbBcC
              (
               sig.s[i]
               , A
               , c_p
               , sig.I
               , c_c
               , D
               );

            c_to_hash[2*n+3] = L;
            c_to_hash[2*n+4] = R;
            hwdev.clsag_hash(c_to_hash,c_new);
            c = c_new;

            i = (i + 1) % n;
            if (i == 0)
                sig.c1 = c;
        }

        // Compute final scalar
        hwdev.clsag_sign(c,a,p,z,mu_P,mu_C,sig.s[l]);
        memwipe(&a, sizeof(key));

        return sig;
    }

    key get_mlsag_pre_hash(const rctSig rv)
    {
      hw::device& hwdev = hw::get_device("default");
      keyV hashes;
      hashes.reserve(3);
      hashes.push_back(rv.message);
      crypto::hash h;

      std::stringstream ss;
      binary_archive<true> ba(ss);
      LOG_ERROR_AND_THROW_UNLESS(!rv.mixRing.empty(), "Empty mixRing");
      const size_t inputs = rv.mixRing.size();
      const size_t outputs = rv.ecdhInfo.size();
      key prehash;
      LOG_ERROR_AND_THROW_UNLESS(const_cast<rctSig&>(rv).serialize_rctsig_base(ba, inputs, outputs),
          "Failed to serialize rctSigBase");
      cryptonote::get_blob_hash(ss.str(), h);
      hashes.push_back(hash2rct(h));

      keyV kv;
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
          kv.push_back(s2k(p.taux));
          kv.push_back(s2k(p.mu));
          for (const auto &l: p.L)
            kv.push_back(l);
          for (const auto &r: p.R)
            kv.push_back(r);
          kv.push_back(s2k(p.a));
          kv.push_back(s2k(p.b));
          kv.push_back(s2k(p.t));
        }
      }
      hashes.push_back(hash_keys(kv));
      hwdev.mlsag_pre_hash(ss.str(), inputs, outputs, hashes, rv.outPk, prehash);
      return  prehash;
    }


    clsag proveRctCLSAGSimple
    (
     const key message
     , const ctkeyV pubs
     , const pri_ctkey inSk
     , const scalar a
     , const key Cout
     , const unsigned int index
     ) {
        //setup vars
        size_t rows = 1;
        size_t cols = pubs.size();
        LOG_ERROR_AND_THROW_UNLESS(cols >= 1, "Empty pubs");
        keyV tmp(rows + 1);
        scalarV sk(rows + 1);
        keyM M(cols, tmp);

        keyV P, C, C_nonzero;
        P.reserve(pubs.size());
        C.reserve(pubs.size());
        C_nonzero.reserve(pubs.size());
        for (const ctkey &k: pubs)
        {
            P.push_back(k.dest);
            C_nonzero.push_back(k.mask);
            rct::key tmp;
            tmp = k.mask - Cout;
            C.push_back(tmp);
        }

        sk[0] = inSk.addr;
        sk[1] = s2s(inSk.blinding_factor - a);
        clsag result = CLSAG_Gen(message, P, sk[0], C, sk[1], C_nonzero, Cout, index);
        memwipe(sk.data(), sk.size() * sizeof(key));
        return result;
    }


    bool verRctCLSAGSimpleMayThrow(const key message, const clsag sig, const ctkeyS pubs, const key C_offset)
    {
        const size_t n = pubs.size();

        // Check data
        LOG_ERROR_AND_RETURN_UNLESS(n >= 1, false, "Empty pubs");
        LOG_ERROR_AND_RETURN_UNLESS(n == sig.s.size(), false, "Signature scalar vector is the wrong size!");
        for (const auto &s: sig.s)
          LOG_ERROR_AND_RETURN_UNLESS(sc_check(s.data) == 0, false, "Bad signature scalar!");
        LOG_ERROR_AND_RETURN_UNLESS(sc_check(sig.c1.data) == 0, false, "Bad signature commitment!");
        LOG_ERROR_AND_RETURN_IF((sig.I == rct::identity), false, "Bad key image!");

        if (!is_valid_point(C_offset)) {
          LOG_ERROR("C_offset is not a valid point: " << C_offset);
          return false;
        }

        // Prepare key images
        scalar c = sig.c1;
        key D_8 = multPoint8(sig.D);
        LOG_ERROR_AND_RETURN_IF((D_8 == rct::identity), false, "Bad auxiliary key image!");

        // Aggregation hashes
        keyV mu_P_to_hash(2*n+4); // domain, I, D, P, C, C_offset
        keyV mu_C_to_hash(2*n+4); // domain, I, D, P, C, C_offset
        sc_0(mu_P_to_hash[0].data);
        memcpy(mu_P_to_hash[0].data,config::HASH_KEY_CLSAG_AGG_0,sizeof(config::HASH_KEY_CLSAG_AGG_0)-1);
        sc_0(mu_C_to_hash[0].data);
        memcpy(mu_C_to_hash[0].data,config::HASH_KEY_CLSAG_AGG_1,sizeof(config::HASH_KEY_CLSAG_AGG_1)-1);
        for (size_t i = 1; i < n+1; ++i) {
            mu_P_to_hash[i] = pubs[i-1].dest;
            mu_C_to_hash[i] = pubs[i-1].dest;
        }
        for (size_t i = n+1; i < 2*n+1; ++i) {
            mu_P_to_hash[i] = pubs[i-n-1].mask;
            mu_C_to_hash[i] = pubs[i-n-1].mask;
        }
        mu_P_to_hash[2*n+1] = sig.I;
        mu_P_to_hash[2*n+2] = sig.D;
        mu_P_to_hash[2*n+3] = C_offset;
        mu_C_to_hash[2*n+1] = sig.I;
        mu_C_to_hash[2*n+2] = sig.D;
        mu_C_to_hash[2*n+3] = C_offset;
        scalar mu_P, mu_C;
        mu_P = hash_keys_to_scalar(mu_P_to_hash);
        mu_C = hash_keys_to_scalar(mu_C_to_hash);

        // Set up round hash
        keyV c_to_hash(2*n+5); // domain, P, C, C_offset, message, L, R
        sc_0(c_to_hash[0].data);
        memcpy(c_to_hash[0].data,config::HASH_KEY_CLSAG_ROUND,sizeof(config::HASH_KEY_CLSAG_ROUND)-1);
        for (size_t i = 1; i < n+1; ++i)
        {
            c_to_hash[i] = pubs[i-1].dest;
            c_to_hash[i+n] = pubs[i-1].mask;
        }
        c_to_hash[2*n+1] = C_offset;
        c_to_hash[2*n+2] = message;
        scalar c_p; // = c[i]*mu_P
        scalar c_c; // = c[i]*mu_C
        scalar c_new;
        key L;
        key R;
        size_t i = 0;

        while (i < n) {
            sc_0(c_new.data);
            c_p = mu_P * c;
            c_c = mu_C * c;

            const key mask = span2rct(epee::pod_to_span(pubs[i].mask.data));
            if (!is_valid_point(mask)) {
              LOG_ERROR("pubs[" << i << "].mask.data is not a valid point: " << mask);
              return false;
            }

            const key C = mask - C_offset;

            // Compute L
            L = addKeys_aGbBcC
              (
               sig.s[i]
               , c_p
               , pubs[i].dest
               , c_c
               , C
               );

            // Compute R
            const key k = hash_to_key_via_f2(pubs[i].dest);

            R = addKeys_aAbBcC
              (
               sig.s[i]
               , k
               , c_p
               , sig.I
               , c_c
               , D_8
               );

            c_to_hash[2*n+3] = L;
            c_to_hash[2*n+4] = R;
            c_new = hash_keys_to_scalar(c_to_hash);
            LOG_ERROR_AND_RETURN_IF((c_new == rct::s_zero), false, "Bad signature hash");
            c = c_new;

            i = i + 1;
        }
        c_new = s2s(c - sig.c1);
        return sc_isnonzero(c_new.data) == 0;
    }

    bool verRctCLSAGSimple(const key message, const clsag sig, const ctkeyS pubs, const key C_offset) {
      try {
        return verRctCLSAGSimpleMayThrow(message, sig, pubs, C_offset);
      }
      catch (...) { return false; }
    }


    void rand_assign_ctkey(ctkey& a) {
        a.mask = pkGen();
        a.dest = pkGen();
    }

    size_t populateRingsSimple(ctkeyV& mixRing, const ctkey inPk, const size_t mixin) {
        size_t index = ((size_t)std::rand()) % (mixin + 1);
        for (size_t i = 0; i <= mixin; i++) {
            if (i != index) {
                rand_assign_ctkey(mixRing[i]);
            } else {
                mixRing[i] = inPk;
            }
        }
        return index;
    }

    rctSig genRctSimple
    (
     const key message
     , const pri_ctkeyV inSk
     , const keyV destinations
     , const vector<amount_t> inamounts
     , const vector<amount_t> outamounts
     , const amount_t txnFee
     , const ctkeyM mixRing
     , const keyV amount_keys
     , const std::vector<size_t> index
     , pri_ctkeyV& outSk
     ) {
        hw::device& hwdev = hw::get_device("default");
        LOG_ERROR_AND_THROW_UNLESS(inamounts.size() > 0, "Empty inamounts");
        LOG_ERROR_AND_THROW_UNLESS(inamounts.size() == inSk.size(), "Different number of inamounts/inSk");
        LOG_ERROR_AND_THROW_UNLESS(outamounts.size() == destinations.size(), "Different number of amounts/destinations");
        LOG_ERROR_AND_THROW_UNLESS(amount_keys.size() == destinations.size(), "Different number of amount_keys/destinations");
        LOG_ERROR_AND_THROW_UNLESS(index.size() == inSk.size(), "Different number of index/inSk");
        LOG_ERROR_AND_THROW_UNLESS(mixRing.size() == inSk.size(), "Different number of mixRing/inSk");
        for (size_t n = 0; n < mixRing.size(); ++n) {
          LOG_ERROR_AND_THROW_UNLESS(index[n] < mixRing[n].size(), "Bad index into mixRing");
        }

        rctSig rv;
        rv.type = RCTTypeCLSAG;
        rv.message = message;
        rv.outPk.resize(destinations.size());
        rv.ecdhInfo.resize(destinations.size());

        size_t i;
        keyV masks(destinations.size()); //sk mask..
        outSk.resize(destinations.size());
        for (i = 0; i < destinations.size(); i++) {

            //add destination to sig
            rv.outPk[i].dest = destinations[i];
            //compute range proof
        }

        rv.p.bulletproofs.clear();
        {
            {
                rct::keyV C;
                rct::scalarV masks;
                const std::span<const key> keys{&amount_keys[0], amount_keys.size()};
                rv.p.bulletproofs.push_back(proveRangeBulletproof(C, masks, outamounts, keys));

                for (i = 0; i < outamounts.size(); ++i)
                {
                    rv.outPk[i].mask = rct::multPoint8(C[i]);
                    outSk[i].blinding_factor = masks[i];
                }
            }
        }

        scalar sumout = s_zero;
        for (i = 0; i < outSk.size(); ++i)
        {
            sumout = outSk[i].blinding_factor + sumout;

            //mask amount and mask
            rv.ecdhInfo[i].mask = outSk[i].blinding_factor;
            rv.ecdhInfo[i].amount = int_to_scalar(outamounts[i]);
            hwdev.ecdhEncode(rv.ecdhInfo[i], amount_keys[i]);
        }

        //set txn fee
        rv.txnFee = txnFee;
//        TODO: unused ??
//        key txnFeeKey = scalarmultH(int_to_scalar(rv.txnFee));
        rv.mixRing = mixRing;
        keyV &pseudoOuts = rv.p.pseudoOuts;
        pseudoOuts.resize(inamounts.size());
        rv.p.CLSAGs.resize(inamounts.size());
        // TODO: scalar
        scalar sumpouts = s_zero; //sum pseudoOut masks
        scalarV a(inamounts.size());
        for (i = 0 ; i < inamounts.size() - 1; i++) {
            a[i] = skGen();
            sumpouts = a[i] + sumpouts;
            pseudoOuts[i] = genC(a[i], inamounts[i]);
        }
        a[i] = s2s(sumout - sumpouts);
        pseudoOuts[i] = genC(a[i], inamounts[i]);

        key full_message = get_mlsag_pre_hash(rv);
        for (i = 0 ; i < inamounts.size(); i++)
        {
            {
                rv.p.CLSAGs[i] = proveRctCLSAGSimple
                  (
                   full_message
                   , rv.mixRing[i]
                   , inSk[i]
                   , a[i]
                   , pseudoOuts[i]
                   , index[i]
                   );
            }
        }
        return rv;
    }

    rctSig genRctSimple
    (
     const key message
     , const pri_ctkeyV inSk
     , const ctkeyV inPk
     , const keyV destinations
     , const std::vector<amount_t> inamounts
     , const std::vector<amount_t> outamounts
     , const keyV amount_keys
     , const amount_t txnFee
     , const size_t mixin
     ) {
        std::vector<size_t> index;
        index.resize(inPk.size());
        ctkeyM mixRing;
        pri_ctkeyV outSk;
        mixRing.resize(inPk.size());
        for (size_t i = 0; i < inPk.size(); ++i) {
          mixRing[i].resize(mixin+1);
          index[i] = populateRingsSimple(mixRing[i], inPk[i], mixin);
        }
        return genRctSimple
          (message, inSk, destinations, inamounts, outamounts, txnFee, mixRing, amount_keys, index, outSk);
    }

    bool verRctSemanticsSimpleMayThrow(const std::span<const rctSig> rvv)
    {
        tools::threadpool& tpool = tools::threadpool::getInstance();
        tools::threadpool::waiter waiter(tpool);
        std::deque<bool> results;
        std::vector<Bulletproof> proofs;
        size_t max_non_bp_proofs = 0;

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

        results.resize(max_non_bp_proofs);
        for (const rctSig& rv: rvv)
        {
          const keyV &pseudoOuts = rv.p.pseudoOuts;

          rct::keyV masks(rv.outPk.size());
          for (size_t i = 0; i < rv.outPk.size(); i++) {
            masks[i] = rv.outPk[i].mask;
          }
          key sumOutpks = addKeys(masks);
          const key txnFeeKey = scalarmultH(int_to_scalar(rv.txnFee));
          sumOutpks = txnFeeKey + sumOutpks;

          key sumPseudoOuts = addKeys(pseudoOuts);

          //check pseudoOuts vs Outs..
          if (sumPseudoOuts != sumOutpks) {
            LOG_PRINT_L1("Sum check failed");
            return false;
          }

          for (size_t i = 0; i < rv.p.bulletproofs.size(); i++) {
            proofs.push_back(rv.p.bulletproofs[i]);
          }
        }
        if (!proofs.empty() && !verBulletproof(proofs))
        {
          LOG_PRINT_L1("Aggregate range proof verified failed");
          return false;
        }

        if (!waiter.wait())
          return false;
        for (size_t i = 0; i < results.size(); ++i) {
          if (!results[i]) {
            LOG_PRINT_L1("Range proof verified failed for proof " << i);
            return false;
          }
        }

        return true;
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

        const keyV &pseudoOuts = rv.p.pseudoOuts;

        const key message = get_mlsag_pre_hash(rv);

        results.clear();
        results.resize(rv.mixRing.size());
        for (size_t i = 0 ; i < rv.mixRing.size() ; i++) {
          tpool.submit(&waiter, [&, i] {
            results[i] = verRctCLSAGSimple(message, rv.p.CLSAGs[i], rv.mixRing[i], pseudoOuts[i]);
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

    amount_t decodeRctSimple(const rctSig rv, const key sk, const unsigned int i, scalar& mask) {
        hw::device& hwdev = hw::get_device("default");
        LOG_ERROR_AND_RETURN_UNLESS(rv.type == RCTTypeCLSAG, false, "decodeRct called on non simple rctSig");
        LOG_ERROR_AND_THROW_UNLESS(i < rv.ecdhInfo.size(), "Bad index");
        LOG_ERROR_AND_THROW_UNLESS(rv.outPk.size() == rv.ecdhInfo.size(), "Mismatched sizes of rv.outPk and rv.ecdhInfo");

        //mask amount and mask
        ecdhTuple ecdh_info = rv.ecdhInfo[i];
        hwdev.ecdhDecode(ecdh_info, sk);
        mask = ecdh_info.mask;
        scalar amount = ecdh_info.amount;
        key C = rv.outPk[i].mask;
        LOG_ERROR_AND_THROW_UNLESS(sc_check(mask.data) == 0, "warning, bad ECDH mask");
        LOG_ERROR_AND_THROW_UNLESS(sc_check(amount.data) == 0, "warning, bad ECDH amount");
        const key Ctmp = addScalarMult_G_H(mask, amount);
        if (C != Ctmp) {
            LOG_ERROR_AND_THROW_UNLESS(false, "warning, amount decoded incorrectly, will be unable to spend");
        }
        return scalar_to_int(amount);
    }
}
