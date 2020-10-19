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
#ifndef RCT_TYPES_H
#define RCT_TYPES_H

#include <cstddef>
#include <vector>
#include <iostream>
#include <cinttypes>
#include <sodium/crypto_verify_32.h>

extern "C" {
#include "crypto/crypto-ops.h"
#include "crypto/random.h"
}
#include "crypto/generic-ops.h"
#include "crypto/crypto.h"

#include "hex.h"
#include "span.h"
#include "memwipe.h"
#include "serialization/containers.h"
#include "serialization/debug_archive.h"
#include "serialization/binary_archive.h"
#include "serialization/json_archive.h"


//Define this flag when debugging to get additional info on the console
#ifdef DBG
#define DP(x) dp(x)
#else
#define DP(x)
#endif

//atomic units of moneros
#define ATOMS 64

//for printing large ints

//Namespace specifically for ring ct code
namespace rct {
    //basic ops containers
    typedef unsigned char * Bytes;

    // Can contain a secret or public key
    //  similar to secret_key / public_key of crypto-ops,
    //  but uses unsigned chars,
    //  also includes an operator for accessing the i'th byte.
    struct key {
        unsigned char & operator[](int i) {
            return bytes[i];
        }
        unsigned char operator[](int i) const {
            return bytes[i];
        }
        bool operator==(const key &k) const { return !crypto_verify_32(bytes, k.bytes); }
        unsigned char bytes[32];
    };
    typedef std::vector<key> keyV; //vector of keys
    typedef std::vector<keyV> keyM; //matrix of keys (indexed by column first)

    //containers For CT operations
    //if it's  representing a private ctkey then "dest" contains the secret key of the address
    // while "mask" contains a where C = aG + bH is CT pedersen commitment and b is the amount
    // (store b, the amount, separately
    //if it's representing a public ctkey, then "dest" = P the address, mask = C the commitment
    struct ctkey {
        key dest;
        key mask; //C here if public
    };
    typedef std::vector<ctkey> ctkeyV;
    typedef std::vector<ctkeyV> ctkeyM;

    //used for multisig data
    struct multisig_kLRki {
        key k;
        key L;
        key R;
        key ki;

        ~multisig_kLRki() { memwipe(&k, sizeof(k)); }
    };

    struct multisig_out {
        std::vector<key> c; // for all inputs
        std::vector<key> mu_p; // for all inputs
        std::vector<key> c0; // for all inputs

        BEGIN_SERIALIZE_OBJECT()
          FIELD(c)
          FIELD(mu_p)
          if (!mu_p.empty() && mu_p.size() != c.size())
            return false;
        END_SERIALIZE()
    };

    //data for passing the amount to the receiver secretly
    // If the pedersen commitment to an amount is C = aG + bH,
    // "mask" contains a 32 byte key a
    // "amount" contains a hex representation (in 32 bytes) of a 64 bit number
    // the purpose of the ECDH exchange
    struct ecdhTuple {
        key mask;
        key amount;

        BEGIN_SERIALIZE_OBJECT()
          FIELD(mask) // not saved from v2 BPs
          FIELD(amount)
        END_SERIALIZE()
    };

    //containers for representing amounts
    typedef uint64_t xmr_amount;
    typedef unsigned int bits[ATOMS];
    typedef key key64[64];

    struct boroSig {
        key64 s0;
        key64 s1;
        key ee;
    };
  
    //Container for precomp
    struct geDsmp {
        ge_dsmp k;
    };
    
    //just contains the necessary keys to represent MLSAG sigs
    //c.f. https://eprint.iacr.org/2015/1098
    struct mgSig {
        keyM ss;
        key cc;
        keyV II;

        BEGIN_SERIALIZE_OBJECT()
            FIELD(ss)
            FIELD(cc)
            // FIELD(II) - not serialized, it can be reconstructed
        END_SERIALIZE()
    };

    // CLSAG signature
    struct clsag {
        keyV s; // scalars
        key c1;

        key I; // signing key image
        key D; // commitment key image

        BEGIN_SERIALIZE_OBJECT()
            FIELD(s)
            FIELD(c1)
            // FIELD(I) - not serialized, it can be reconstructed
            FIELD(D)
        END_SERIALIZE()
    };

    //contains the data for an Borromean sig
    // also contains the "Ci" values such that
    // \sum Ci = C
    // and the signature proves that each Ci is either
    // a Pedersen commitment to 0 or to 2^i
    //thus proving that C is in the range of [0, 2^64]
    struct rangeSig {
        boroSig asig;
        key64 Ci;

        BEGIN_SERIALIZE_OBJECT()
            FIELD(asig)
            FIELD(Ci)
        END_SERIALIZE()
    };

    struct Bulletproof
    {
      rct::keyV V;
      rct::key A, S, T1, T2;
      rct::key taux, mu;
      rct::keyV L, R;
      rct::key a, b, t;

      Bulletproof():
        A({}), S({}), T1({}), T2({}), taux({}), mu({}), a({}), b({}), t({}) {}
      Bulletproof(const rct::key &V, const rct::key &A, const rct::key &S, const rct::key &T1, const rct::key &T2, const rct::key &taux, const rct::key &mu, const rct::keyV &L, const rct::keyV &R, const rct::key &a, const rct::key &b, const rct::key &t):
        V({V}), A(A), S(S), T1(T1), T2(T2), taux(taux), mu(mu), L(L), R(R), a(a), b(b), t(t) {}
      Bulletproof(const rct::keyV &V, const rct::key &A, const rct::key &S, const rct::key &T1, const rct::key &T2, const rct::key &taux, const rct::key &mu, const rct::keyV &L, const rct::keyV &R, const rct::key &a, const rct::key &b, const rct::key &t):
        V(V), A(A), S(S), T1(T1), T2(T2), taux(taux), mu(mu), L(L), R(R), a(a), b(b), t(t) {}

      bool operator==(const Bulletproof &other) const { return V == other.V && A == other.A && S == other.S && T1 == other.T1 && T2 == other.T2 && taux == other.taux && mu == other.mu && L == other.L && R == other.R && a == other.a && b == other.b && t == other.t; }

      BEGIN_SERIALIZE_OBJECT()
        // Commitments aren't saved, they're restored via outPk
        // FIELD(V)
        FIELD(A)
        FIELD(S)
        FIELD(T1)
        FIELD(T2)
        FIELD(taux)
        FIELD(mu)
        FIELD(L)
        FIELD(R)
        FIELD(a)
        FIELD(b)
        FIELD(t)

        if (L.empty() || L.size() != R.size())
          return false;
      END_SERIALIZE()
    };

    size_t n_bulletproof_amounts(const Bulletproof &proof);
    size_t n_bulletproof_max_amounts(const Bulletproof &proof);
    size_t n_bulletproof_amounts(const std::vector<Bulletproof> &proofs);
    size_t n_bulletproof_max_amounts(const std::vector<Bulletproof> &proofs);

    //A container to hold all signatures necessary for RingCT
    // rangeSigs holds all the rangeproof data of a transaction
    // MG holds the MLSAG signature of a transaction
    // mixRing holds all the public keypairs (P, C) for a transaction
    // ecdhInfo holds an encoded mask / amount to be passed to each receiver
    // outPk contains public keypairs which are destinations (P, C),
    //  P = address, C = commitment to amount
    enum {
      RCTTypeNull = 0,
      RCTTypeBulletproof = 3,
      RCTTypeBulletproof2 = 4,
      RCTTypeCLSAG = 5,
    };
    enum RangeProofType { RangeProofBorromean, RangeProofBulletproof, RangeProofMultiOutputBulletproof, RangeProofPaddedBulletproof };
    struct RCTConfig {
      RangeProofType range_proof_type;
      int bp_version;

      BEGIN_SERIALIZE_OBJECT()
        VERSION_FIELD(0)
        VARINT_FIELD(range_proof_type)
        VARINT_FIELD(bp_version)
      END_SERIALIZE()
    };

    const int lol_bp_version = 3;
    const RCTConfig lol_rct_config {
      RangeProofPaddedBulletproof,
      lol_bp_version,
    };

    struct rctSigBase {
        uint8_t type;
        key message;
        ctkeyM mixRing; //the set of all pubkeys / copy
        //pairs that you mix with
        keyV pseudoOuts; //C - for simple rct
        std::vector<ecdhTuple> ecdhInfo;
        ctkeyV outPk;
        xmr_amount txnFee; // contains b

        template<bool W, template <bool> class Archive>
        bool serialize_rctsig_base(Archive<W> &ar, size_t inputs, size_t outputs)
        {
          FIELD(type)
          if (type == RCTTypeNull)
            return ar.stream().good();
          if (type != RCTTypeBulletproof && type != RCTTypeBulletproof2 && type != RCTTypeCLSAG)
            return false;
          VARINT_FIELD(txnFee)
          // inputs/outputs not saved, only here for serialization help
          // FIELD(message) - not serialized, it can be reconstructed
          // FIELD(mixRing) - not serialized, it can be reconstructed
          ar.tag("ecdhInfo");
          ar.begin_array();
          PREPARE_CUSTOM_VECTOR_SERIALIZATION(outputs, ecdhInfo);
          if (ecdhInfo.size() != outputs)
            return false;
          for (size_t i = 0; i < outputs; ++i)
          {
            if (type == RCTTypeBulletproof2 || type == RCTTypeCLSAG)
            {
              ar.begin_object();
              if (!typename Archive<W>::is_saving())
                memset(ecdhInfo[i].amount.bytes, 0, sizeof(ecdhInfo[i].amount.bytes));
              crypto::hash8 &amount = (crypto::hash8&)ecdhInfo[i].amount;
              FIELD(amount);
              ar.end_object();
            }
            else
            {
              FIELDS(ecdhInfo[i])
            }
            if (outputs - i > 1)
              ar.delimit_array();
          }
          ar.end_array();

          ar.tag("outPk");
          ar.begin_array();
          PREPARE_CUSTOM_VECTOR_SERIALIZATION(outputs, outPk);
          if (outPk.size() != outputs)
            return false;
          for (size_t i = 0; i < outputs; ++i)
          {
            FIELDS(outPk[i].mask)
            if (outputs - i > 1)
              ar.delimit_array();
          }
          ar.end_array();
          return ar.stream().good();
        }

        BEGIN_SERIALIZE_OBJECT()
          FIELD(type)
          FIELD(message)
          FIELD(mixRing)
          FIELD(pseudoOuts)
          FIELD(ecdhInfo)
          FIELD(outPk)
          VARINT_FIELD(txnFee)
        END_SERIALIZE()
    };
    struct rctSigPrunable {
        std::vector<rangeSig> rangeSigs;
        std::vector<Bulletproof> bulletproofs;
        std::vector<mgSig> MGs; // simple rct has N, full has 1
        std::vector<clsag> CLSAGs;
        keyV pseudoOuts; //C - for simple rct

        // when changing this function, update cryptonote::get_pruned_transaction_weight
        template<bool W, template <bool> class Archive>
        bool serialize_rctsig_prunable(Archive<W> &ar, uint8_t type, size_t inputs, size_t outputs, size_t mixin)
        {
          if (inputs >= 0xffffffff)
            return false;
          if (outputs >= 0xffffffff)
            return false;
          if (mixin >= 0xffffffff)
            return false;
          if (type == RCTTypeNull)
            return ar.stream().good();
          if (type != RCTTypeBulletproof && type != RCTTypeBulletproof2 && type != RCTTypeCLSAG)
            return false;
          if (type == RCTTypeBulletproof || type == RCTTypeBulletproof2 || type == RCTTypeCLSAG)
          {
            uint32_t nbp = bulletproofs.size();
            if (type == RCTTypeBulletproof2 || type == RCTTypeCLSAG)
              VARINT_FIELD(nbp)
            else
              FIELD(nbp)
            ar.tag("bp");
            ar.begin_array();
            if (nbp > outputs)
              return false;
            PREPARE_CUSTOM_VECTOR_SERIALIZATION(nbp, bulletproofs);
            for (size_t i = 0; i < nbp; ++i)
            {
              FIELDS(bulletproofs[i])
              if (nbp - i > 1)
                ar.delimit_array();
            }
            if (n_bulletproof_max_amounts(bulletproofs) < outputs)
              return false;
            ar.end_array();
          }
          else
          {
            ar.tag("rangeSigs");
            ar.begin_array();
            PREPARE_CUSTOM_VECTOR_SERIALIZATION(outputs, rangeSigs);
            if (rangeSigs.size() != outputs)
              return false;
            for (size_t i = 0; i < outputs; ++i)
            {
              FIELDS(rangeSigs[i])
              if (outputs - i > 1)
                ar.delimit_array();
            }
            ar.end_array();
          }

          if (type == RCTTypeCLSAG)
          {
            ar.tag("CLSAGs");
            ar.begin_array();
            PREPARE_CUSTOM_VECTOR_SERIALIZATION(inputs, CLSAGs);
            if (CLSAGs.size() != inputs)
              return false;
            for (size_t i = 0; i < inputs; ++i)
            {
              // we save the CLSAGs contents directly, because we want it to save its
              // arrays without the size prefixes, and the load can't know what size
              // to expect if it's not in the data
              ar.begin_object();
              ar.tag("s");
              ar.begin_array();
              PREPARE_CUSTOM_VECTOR_SERIALIZATION(mixin + 1, CLSAGs[i].s);
              if (CLSAGs[i].s.size() != mixin + 1)
                return false;
              for (size_t j = 0; j <= mixin; ++j)
              {
                FIELDS(CLSAGs[i].s[j])
                if (mixin + 1 - j > 1)
                  ar.delimit_array();
              }
              ar.end_array();

              ar.tag("c1");
              FIELDS(CLSAGs[i].c1)

              // CLSAGs[i].I not saved, it can be reconstructed
              ar.tag("D");
              FIELDS(CLSAGs[i].D)
              ar.end_object();

              if (inputs - i > 1)
                 ar.delimit_array();
            }

            ar.end_array();
          }
          else
          {
            ar.tag("MGs");
            ar.begin_array();
            // we keep a byte for size of MGs, because we don't know whether this is
            // a simple or full rct signature, and it's starting to annoy the hell out of me
            size_t mg_elements = (type == RCTTypeBulletproof || type == RCTTypeBulletproof2) ? inputs : 1;
            PREPARE_CUSTOM_VECTOR_SERIALIZATION(mg_elements, MGs);
            if (MGs.size() != mg_elements)
              return false;
            for (size_t i = 0; i < mg_elements; ++i)
            {
              // we save the MGs contents directly, because we want it to save its
              // arrays and matrices without the size prefixes, and the load can't
              // know what size to expect if it's not in the data
              ar.begin_object();
              ar.tag("ss");
              ar.begin_array();
              PREPARE_CUSTOM_VECTOR_SERIALIZATION(mixin + 1, MGs[i].ss);
              if (MGs[i].ss.size() != mixin + 1)
                return false;
              for (size_t j = 0; j < mixin + 1; ++j)
              {
                ar.begin_array();
                size_t mg_ss2_elements = ((type == RCTTypeBulletproof || type == RCTTypeBulletproof2) ? 1 : inputs) + 1;
                PREPARE_CUSTOM_VECTOR_SERIALIZATION(mg_ss2_elements, MGs[i].ss[j]);
                if (MGs[i].ss[j].size() != mg_ss2_elements)
                  return false;
                for (size_t k = 0; k < mg_ss2_elements; ++k)
                {
                  FIELDS(MGs[i].ss[j][k])
                  if (mg_ss2_elements - k > 1)
                    ar.delimit_array();
                }
                ar.end_array();
  
                if (mixin + 1 - j > 1)
                  ar.delimit_array();
              }
              ar.end_array();

              ar.tag("cc");
              FIELDS(MGs[i].cc)
              // MGs[i].II not saved, it can be reconstructed
              ar.end_object();

              if (mg_elements - i > 1)
                 ar.delimit_array();
            }
            ar.end_array();
          }
          if (type == RCTTypeBulletproof || type == RCTTypeBulletproof2 || type == RCTTypeCLSAG)
          {
            ar.tag("pseudoOuts");
            ar.begin_array();
            PREPARE_CUSTOM_VECTOR_SERIALIZATION(inputs, pseudoOuts);
            if (pseudoOuts.size() != inputs)
              return false;
            for (size_t i = 0; i < inputs; ++i)
            {
              FIELDS(pseudoOuts[i])
              if (inputs - i > 1)
                ar.delimit_array();
            }
            ar.end_array();
          }
          return ar.stream().good();
        }

        BEGIN_SERIALIZE_OBJECT()
          FIELD(rangeSigs)
          FIELD(bulletproofs)
          FIELD(MGs)
          FIELD(CLSAGs)
          FIELD(pseudoOuts)
        END_SERIALIZE()
    };
    struct rctSig: public rctSigBase {
        rctSigPrunable p;

        keyV& get_pseudo_outs()
        {
          return type == RCTTypeBulletproof || type == RCTTypeBulletproof2 || type == RCTTypeCLSAG ? p.pseudoOuts : pseudoOuts;
        }

        keyV const& get_pseudo_outs() const
        {
          return type == RCTTypeBulletproof || type == RCTTypeBulletproof2 || type == RCTTypeCLSAG ? p.pseudoOuts : pseudoOuts;
        }

        BEGIN_SERIALIZE_OBJECT()
          FIELDS((rctSigBase&)*this)
          FIELD(p)
        END_SERIALIZE()
    };

    //Debug printing for the above types
    //Actually use DP(value) and #define DBG
    void dp(key a);
    void dp(bool a);
    void dp(const char * a, int l);
    void dp(keyV a);
    void dp(keyM a);
    void dp(xmr_amount vali);
    void dp(int vali);
    void dp(bits amountb);
    void dp(const char * st);

    //various conversions

    //uint long long to 32 byte key
    void d2h(key & amounth, xmr_amount val);
    key d2h(xmr_amount val);
    //uint long long to int[64]
    void d2b(bits  amountb, xmr_amount val);
    //32 byte key to uint long long
    // if the key holds a value > 2^64
    // then the value in the first 8 bytes is returned
    xmr_amount h2d(const key &test);
    //32 byte key to int[64]
    void h2b(bits  amountb2, const key & test);
    //int[64] to 32 byte key
    void b2h(key  & amountdh, bits amountb2);
    //int[64] to uint long long
    xmr_amount b2d(bits amountb);

    bool is_rct_simple(int type);
    bool is_rct_bulletproof(int type);

    static inline const rct::key &pk2rct(const crypto::public_key &pk) { return (const rct::key&)pk; }
    static inline const rct::key &sk2rct(const crypto::secret_key &sk) { return (const rct::key&)sk; }
    static inline const rct::key &ki2rct(const crypto::key_image &ki) { return (const rct::key&)ki; }
    static inline const rct::key &hash2rct(const crypto::hash &h) { return (const rct::key&)h; }
    static inline const crypto::public_key &rct2pk(const rct::key &k) { return (const crypto::public_key&)k; }
    static inline const crypto::secret_key &rct2sk(const rct::key &k) { return (const crypto::secret_key&)k; }
    static inline const crypto::key_image &rct2ki(const rct::key &k) { return (const crypto::key_image&)k; }
    static inline const crypto::hash &rct2hash(const rct::key &k) { return (const crypto::hash&)k; }
    static inline bool operator==(const rct::key &k0, const crypto::public_key &k1) { return !crypto_verify_32(k0.bytes, (const unsigned char*)&k1); }
    static inline bool operator!=(const rct::key &k0, const crypto::public_key &k1) { return crypto_verify_32(k0.bytes, (const unsigned char*)&k1); }
}


namespace cryptonote {
    static inline bool operator==(const crypto::public_key &k0, const rct::key &k1) { return !crypto_verify_32((const unsigned char*)&k0, k1.bytes); }
    static inline bool operator!=(const crypto::public_key &k0, const rct::key &k1) { return crypto_verify_32((const unsigned char*)&k0, k1.bytes); }
    static inline bool operator==(const crypto::secret_key &k0, const rct::key &k1) { return !crypto_verify_32((const unsigned char*)&k0, k1.bytes); }
    static inline bool operator!=(const crypto::secret_key &k0, const rct::key &k1) { return crypto_verify_32((const unsigned char*)&k0, k1.bytes); }
}

namespace rct {
inline std::ostream &operator <<(std::ostream &o, const rct::key &v) {
  epee::to_hex::formatted(o, epee::as_byte_span(v)); return o;
}
}


namespace std
{
  template<> struct hash<rct::key> { std::size_t operator()(const rct::key &k) const { return reinterpret_cast<const std::size_t&>(k); } };
}

BLOB_SERIALIZER(rct::key);
BLOB_SERIALIZER(rct::key64);
BLOB_SERIALIZER(rct::ctkey);
BLOB_SERIALIZER(rct::multisig_kLRki);
BLOB_SERIALIZER(rct::boroSig);

VARIANT_TAG(debug_archive, rct::key, "rct::key");
VARIANT_TAG(debug_archive, rct::key64, "rct::key64");
VARIANT_TAG(debug_archive, rct::keyV, "rct::keyV");
VARIANT_TAG(debug_archive, rct::keyM, "rct::keyM");
VARIANT_TAG(debug_archive, rct::ctkey, "rct::ctkey");
VARIANT_TAG(debug_archive, rct::ctkeyV, "rct::ctkeyV");
VARIANT_TAG(debug_archive, rct::ctkeyM, "rct::ctkeyM");
VARIANT_TAG(debug_archive, rct::ecdhTuple, "rct::ecdhTuple");
VARIANT_TAG(debug_archive, rct::mgSig, "rct::mgSig");
VARIANT_TAG(debug_archive, rct::rangeSig, "rct::rangeSig");
VARIANT_TAG(debug_archive, rct::boroSig, "rct::boroSig");
VARIANT_TAG(debug_archive, rct::rctSig, "rct::rctSig");
VARIANT_TAG(debug_archive, rct::Bulletproof, "rct::bulletproof");
VARIANT_TAG(debug_archive, rct::multisig_kLRki, "rct::multisig_kLRki");
VARIANT_TAG(debug_archive, rct::multisig_out, "rct::multisig_out");
VARIANT_TAG(debug_archive, rct::clsag, "rct::clsag");

VARIANT_TAG(binary_archive, rct::key, 0x90);
VARIANT_TAG(binary_archive, rct::key64, 0x91);
VARIANT_TAG(binary_archive, rct::keyV, 0x92);
VARIANT_TAG(binary_archive, rct::keyM, 0x93);
VARIANT_TAG(binary_archive, rct::ctkey, 0x94);
VARIANT_TAG(binary_archive, rct::ctkeyV, 0x95);
VARIANT_TAG(binary_archive, rct::ctkeyM, 0x96);
VARIANT_TAG(binary_archive, rct::ecdhTuple, 0x97);
VARIANT_TAG(binary_archive, rct::mgSig, 0x98);
VARIANT_TAG(binary_archive, rct::rangeSig, 0x99);
VARIANT_TAG(binary_archive, rct::boroSig, 0x9a);
VARIANT_TAG(binary_archive, rct::rctSig, 0x9b);
VARIANT_TAG(binary_archive, rct::Bulletproof, 0x9c);
VARIANT_TAG(binary_archive, rct::multisig_kLRki, 0x9d);
VARIANT_TAG(binary_archive, rct::multisig_out, 0x9e);
VARIANT_TAG(binary_archive, rct::clsag, 0x9f);

VARIANT_TAG(json_archive, rct::key, "rct_key");
VARIANT_TAG(json_archive, rct::key64, "rct_key64");
VARIANT_TAG(json_archive, rct::keyV, "rct_keyV");
VARIANT_TAG(json_archive, rct::keyM, "rct_keyM");
VARIANT_TAG(json_archive, rct::ctkey, "rct_ctkey");
VARIANT_TAG(json_archive, rct::ctkeyV, "rct_ctkeyV");
VARIANT_TAG(json_archive, rct::ctkeyM, "rct_ctkeyM");
VARIANT_TAG(json_archive, rct::ecdhTuple, "rct_ecdhTuple");
VARIANT_TAG(json_archive, rct::mgSig, "rct_mgSig");
VARIANT_TAG(json_archive, rct::rangeSig, "rct_rangeSig");
VARIANT_TAG(json_archive, rct::boroSig, "rct_boroSig");
VARIANT_TAG(json_archive, rct::rctSig, "rct_rctSig");
VARIANT_TAG(json_archive, rct::Bulletproof, "rct_bulletproof");
VARIANT_TAG(json_archive, rct::multisig_kLRki, "rct_multisig_kLR");
VARIANT_TAG(json_archive, rct::multisig_out, "rct_multisig_out");
VARIANT_TAG(json_archive, rct::clsag, "rct_clsag");

#endif  /* RCTTYPES_H */
