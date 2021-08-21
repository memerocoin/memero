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

#include "math/ringct/controller/rctGen.hpp"

#include "cryptonote/basic/cryptonote_format_utils.h"

#include "tools/common/threadpool.h"
#include "tools/epee/include/logging.hpp"


#include "config/cryptonote.hpp"

using namespace std;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

namespace rct {
  std::tuple<rct_scalarV, Bulletproof> makeRangeBulletproof
    (
       const std::vector<uint64_t> amounts
     , const std::span<const rct_scalar> sk)
    {
        LOG_ERROR_AND_THROW_UNLESS(amounts.size() == sk.size(), "Invalid amounts/sk sizes");

        rct_scalarV blinding_factors;
        std::transform
          (
           sk.begin()
           , sk.end()
           , std::back_inserter(blinding_factors)
           , [](const auto& x) {
             return rct::get_blinding_factor_from_ecdh_shared_secret(x);
           }
           );

        Bulletproof proof = bulletproof_MAKE(amounts, blinding_factors);
        LOG_ERROR_AND_THROW_UNLESS(proof.V.size() == amounts.size(), "V does not have the expected size");

        return {blinding_factors, proof};
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
     const crypto::hash message
     , const rct_pointV P
     , const rct_scalar p
     , const rct_pointV C
     , const rct_scalar z
     , const rct_pointV C_nonzero
     , const rct_point C_offset
     , const unsigned int l
     ) {
        hw::device& hwdev = hw::get_device("default");
        clsag sig;
        size_t n = P.size(); // ring size
        LOG_ERROR_AND_THROW_UNLESS(n == C.size(), "Signing and commitment rct_point vector sizes must match!");
        LOG_ERROR_AND_THROW_UNLESS(n == C_nonzero.size(), "Signing and commitment rct_point vector sizes must match!");
        LOG_ERROR_AND_THROW_UNLESS(l < n, "Signing index out of range!");

        // mages images
        rct_point H = hash_to_point_via_f2(P[l]);

        rct_point D;

        // Initial values
        rct_scalar a;
        rct_point aG;
        rct_point aH;

        {
          hwdev.clsag_prepare(p,z,sig.I,D,H,a,aG,aH);
        }

        // Offset key image
        sig.D = multP(D, rct::s_inv_eight);

        // Aggregation hashes
        crypto::dataV mu_P_to_hash(2*n+4); // domain, I, D, P, C, C_offset
        crypto::dataV mu_C_to_hash(2*n+4); // domain, I, D, P, C, C_offset
        mu_P_to_hash[0] = zero;
        std::copy_n
          (
           config::HASH_KEY_CLSAG_AGG_0
           , sizeof(config::HASH_KEY_CLSAG_AGG_0)-1
           , mu_P_to_hash[0].data.begin()
           );

        mu_C_to_hash[0] = zero;
        std::copy_n
          (
           config::HASH_KEY_CLSAG_AGG_1
           , sizeof(config::HASH_KEY_CLSAG_AGG_1)-1
           , mu_C_to_hash[0].data.begin()
           );

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
        rct_scalar mu_P, mu_C;
        mu_P = hash_dataV_to_scalar(mu_P_to_hash);
        mu_C = hash_dataV_to_scalar(mu_C_to_hash);

        // Initial commitment
        crypto::dataV c_to_hash(2*n+5); // domain, P, C, C_offset, message, aG, aH
        rct_scalar c;
        c_to_hash[0] = zero;
        std::copy_n
          (
           config::HASH_KEY_CLSAG_ROUND
           , sizeof(config::HASH_KEY_CLSAG_ROUND)-1
           , c_to_hash[0].data.begin()
           );

        for (size_t i = 1; i < n+1; ++i)
        {
            c_to_hash[i] = P[i-1];
            c_to_hash[i+n] = C_nonzero[i-1];
        }
        c_to_hash[2*n+1] = C_offset;
        c_to_hash[2*n+2] = crypto::h2d(message);

        {
            c_to_hash[2*n+3] = aG;
            c_to_hash[2*n+4] = aH;
        }
        c = hwdev.clsag_hash(c_to_hash);

        size_t i;
        i = (l + 1) % n;
        if (i == 0)
            sig.c1 = c;

        // Decoy indices
        sig.s = rct_scalarV(n);
        rct_point L;
        rct_point R;
        rct_scalar c_p; // = c[i]*mu_P
        rct_scalar c_c; // = c[i]*mu_C

        while (i != l) {
            sig.s[i] = skGen();
            c_p = mu_P * c;
            c_c = mu_C * c;

            // Compute L
            L = addPoints
              (
               std::array
               {
                 multG(sig.s[i])
                 , multP(P[i], c_p)
                 , multP(C[i], c_c)
               }
               );

            // Compute R
            const rct_point A = hash_to_point_via_f2(P[i]);
            R = addPoints
              (
               std::array
               {
                 multP(A, sig.s[i])
                 , multP(sig.I, c_p)
                 , multP(D, c_c)
               }
               );

            c_to_hash[2*n+3] = L;
            c_to_hash[2*n+4] = R;
            c = hwdev.clsag_hash(c_to_hash);

            i = (i + 1) % n;
            if (i == 0)
                sig.c1 = c;
        }

        // Compute final scalar
        hwdev.clsag_sign(c,a,p,z,mu_P,mu_C,sig.s[l]);

        return sig;
    }


    void rand_assign_ct_public_key(ct_public_key& a) {
        a.dest = pkGen();
        a.commit_of_amount = pkGen();
    }

    size_t populateRingsSimple(ct_public_keyV& mixRing, const ct_public_key inPk, const size_t mixin) {
        size_t index = ((size_t)std::rand()) % (mixin + 1);
        for (size_t i = 0; i <= mixin; i++) {
            if (i != index) {
                rand_assign_ct_public_key(mixRing[i]);
            } else {
                mixRing[i] = inPk;
            }
        }
        return index;
    }

  std::pair<rctSig, ct_secret_keyV> genRctSimple
    (
     const crypto::hash message
     , const ct_secret_keyV inSk
     , const rct_pointV destinations
     , const vector<amount_t> inamounts
     , const vector<amount_t> outamounts
     , const amount_t txnFee
     , const ct_public_keyM mixRing
     , const rct_scalarV amount_keys
     , const std::vector<size_t> index
     ) {
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

        const auto [blinding_factors, proof] = makeRangeBulletproof(outamounts, amount_keys);
        rv.p.bulletproofs = {proof};

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

        rv.outPk = outPk;


        std::vector<ecdhData> ecdhInfo;
        std::transform
          (
           outamounts.begin(),
           outamounts.end(),
           amount_keys.begin(),
           std::back_inserter(ecdhInfo),
           [](const auto& x, const auto& y) -> ecdhData {
             return {crypto::d2s(encode_by_ecdh_shared_secret(int_to_scalar(x), y))};
           }
           );

        rv.ecdhInfo = ecdhInfo;

        rct_scalar sum_blinding_factors = std::accumulate
          (
           outSk.begin()
           , outSk.end()
           , s_zero
           , [](const auto& x, const auto& y) {
             return x + y.blinding_factor;
           }
           );

        //set txn fee
        rv.txnFee = txnFee;
        rv.mixRing = mixRing;

        // reserve the last one for generating a balanced pseudo sum
        rct_scalarV pseudo_blinding_factors(inamounts.size() - 1);
        std::generate
          (
           pseudo_blinding_factors.begin()
           , pseudo_blinding_factors.end()
           , []() { return skGen(); }
           );

        rct_scalar pseudo_sum_blinding_factors =
          std::accumulate
          (
           pseudo_blinding_factors.begin()
           , pseudo_blinding_factors.end()
           , s_zero
           , std::plus<>()
           );

        rct_pointV pseudoOuts;
        std::transform
          (
           pseudo_blinding_factors.begin()
           , pseudo_blinding_factors.end()
           , inamounts.begin()
           , std::back_inserter(pseudoOuts)
           , [](const auto& x, const auto& y) -> rct_point {
             return commit(x, y);
           }
           );

        pseudo_blinding_factors.push_back(s2s(sum_blinding_factors - pseudo_sum_blinding_factors));
        pseudoOuts.push_back(commit(pseudo_blinding_factors.back(), inamounts.back()));

        rv.p.pseudoOuts = pseudoOuts;

        crypto::hash full_message = get_mlsag_pre_hash(rv);
        std::vector<clsag> clsags(inamounts.size());
        std::generate
          (
           clsags.begin()
           , clsags.end()
           , [full_message, rv, inSk, pseudo_blinding_factors, pseudoOuts, index, i = 0]() mutable {
             const auto clsag = proveRctCLSAGSimple
               (
                full_message
                , rv.mixRing[i]
                , inSk[i]
                , pseudo_blinding_factors[i]
                , pseudoOuts[i]
                , index[i]
                );
             i++;
             return clsag;
           }
           );

        rv.p.CLSAGs = clsags;
        return {rv, outSk};
    }

    clsag proveRctCLSAGSimple
    (
     const crypto::hash message
     , const ct_public_keyV pubs
     , const ct_secret_key inSk
     , const rct_scalar a
     , const rct_point Cout
     , const unsigned int index
     ) {
        //setup vars
        size_t rows = 1;
        size_t cols = pubs.size();
        LOG_ERROR_AND_THROW_UNLESS(cols >= 1, "Empty pubs");
        rct_pointV tmp(rows + 1);
        rct_scalarV sk(rows + 1);
        rct_pointM M(cols, tmp);

        rct_pointV P, C, C_nonzero;
        P.reserve(pubs.size());
        C.reserve(pubs.size());
        C_nonzero.reserve(pubs.size());
        for (const ct_public_key &k: pubs)
        {
            P.push_back(k.dest);
            C_nonzero.push_back(k.commit_of_amount);
            rct::rct_point tmp;
            tmp = k.commit_of_amount - Cout;
            C.push_back(tmp);
        }

        sk[0] = inSk.addr;
        sk[1] = s2s(inSk.blinding_factor - a);
        clsag result = CLSAG_Gen
          (message, P, sk[0], C, sk[1], C_nonzero, Cout, index);
        return result;
    }

    rctSig genRctSimple
    (
     const crypto::hash message
     , const ct_secret_keyV inSk
     , const ct_public_keyV inPk
     , const rct_pointV destinations
     , const std::vector<amount_t> inamounts
     , const std::vector<amount_t> outamounts
     , const rct_scalarV amount_keys
     , const amount_t txnFee
     , const size_t mixin
     ) {
        std::vector<size_t> index;
        index.resize(inPk.size());
        ct_public_keyM mixRing;
        mixRing.resize(inPk.size());
        for (size_t i = 0; i < inPk.size(); ++i) {
          mixRing[i].resize(mixin+1);
          index[i] = populateRingsSimple(mixRing[i], inPk[i], mixin);
        }
        return genRctSimple
          (message, inSk, destinations, inamounts, outamounts, txnFee, mixRing, amount_keys, index).first;
    }

}
