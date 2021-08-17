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

#include "math/crypto/crypto.hpp"

#include "tools/serialization/containers.h"

#include <sodium/crypto_verify_32.h>

#include <span>


//Namespace specifically for ring ct code
namespace rct {
    // Can contain a secret or public key
    //  similar to secret_key / public_key of crypto-ops,
    //  but uses unsigned chars,
    //  also includes an operator for accessing the i'th byte.
    struct rct_point : crypto::ec_point {
      rct_point operator+(const rct_point& y) const;
      rct_point operator-(const rct_point& y) const;

      rct_point operator*(const uint64_t x) const;
      bool operator<(const rct_point& y) const;
    };


    using inv8 = crypto::ec_point_unsafe;
    using reconstructed_key = rct::rct_point;


    struct scalar : crypto::ec_scalar {
      scalar operator+(const scalar& y) const;
      scalar operator-(const scalar& y) const;
      scalar operator*(const scalar& y) const;
    };

    using rct_pointV = std::vector<rct_point>; //vector of keys
    using rct_pointM = std::vector<rct_pointV>; //matrix of keys (indexed by column first)
    using rct_pointS = std::span<const rct_point>; //vector of keys
    using rct_pointL = std::list<const rct_point>; //vector of keys

    using scalarV = std::vector<scalar>; //vector of keys
    using scalarM = std::vector<scalarV>; //matrix of keys (indexed by column first)
    using scalarS = std::span<const scalar>; //vector of keys
    using scalarL = std::list<scalar>; //vector of keys

    using inv8V = std::vector<inv8>; //vector of keys
    using inv8S = std::span<const inv8>; //vector of keys
    using inv8L = std::list<const inv8>; //vector of keys


    //containers For CT operations
    //if it's  representing a private ctkey then "dest" contains the secret rct_point of the address
    // while "mask" contains a where C = aG + bH is CT pedersen commitment and b is the amount
    // (store b, the amount, separately
    //if it's representing a public ctkey, then "dest" = P the address, mask = aG the commitment
    struct ctkey {
        rct_point dest;
        rct_point mask; //C here if public
    };
    typedef std::vector<ctkey> ctrct_pointV;
    typedef std::vector<ctrct_pointV> ctrct_pointM;
    typedef std::span<const ctkey> ctrct_pointS;

    struct pri_ctkey {
      scalar addr;
      scalar blinding_factor; //C here if public
    };

    typedef std::vector<pri_ctkey> pri_ctrct_pointV;
    typedef std::vector<pri_ctrct_pointV> pri_ctrct_pointM;
    typedef std::span<const pri_ctkey> pri_ctrct_pointS;

    //data for passing the amount to the receiver secretly
    // If the pedersen commitment to an amount is C = aG + bH,
    // "mask" contains a 32 byte rct_point a
    // "amount" contains a hex representation (in 32 bytes) of a 64 bit number
    // the purpose of the ECDH exchange
    struct ecdhTuple {
        scalar mask;
        crypto::ec_scalar_unnormalized amount;

        BEGIN_SERIALIZE_OBJECT()
          FIELD(mask) // not saved from v2 BPs
          FIELD(amount)
        END_SERIALIZE()
    };

    //containers for representing amounts
    typedef uint64_t amount_t;

    // CLSAG signature
    struct clsag {
        scalarV s; // scalars
        scalar c1;

        reconstructed_key I; // signing rct_point image
        inv8 D; // commitment rct_point image

        BEGIN_SERIALIZE_OBJECT()
            FIELD(s)
            FIELD(c1)
            // FIELD(I) - not serialized, it can be reconstructed
            FIELD(D)
        END_SERIALIZE()
    };

    struct Bulletproof
    {
      rct::inv8V V;
      rct::inv8 A, S;
      inv8 T1, T2;
      rct::scalar taux;
      rct::scalar mu;
      rct::inv8V L, R;
      rct::scalar a, b, t;

      Bulletproof():
        A({}), S({}), T1({}), T2({}), taux({}), mu({}), a({}), b({}), t({}) {}
      Bulletproof
      (
       const rct::inv8 &V
       , const rct::inv8 &A, const rct::inv8 &S
       , const rct::inv8 &T1, const rct::inv8 &T2
       , const rct::scalar &taux, const rct::scalar &mu
       , const rct::inv8V &L, const rct::inv8V &R
       , const rct::scalar &a, const rct::scalar &b, const rct::scalar &t
       ):
        V({V}), A(A), S(S), T1(T1), T2(T2), taux(taux), mu(mu), L(L), R(R), a(a), b(b), t(t) {}

      Bulletproof
      (
       const rct::inv8V &V, const rct::inv8 &A, const rct::inv8 &S
       , const rct::inv8 &T1, const rct::inv8 &T2
       , const rct::scalar &taux, const rct::scalar &mu
       , const rct::inv8V &L, const rct::inv8V &R
       , const rct::scalar &a, const rct::scalar &b, const rct::scalar &t
       ):
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

    struct rctSigBase {
        uint8_t type;
        crypto::hash message;
        ctrct_pointM mixRing; //the set of all pubkeys / copy
        //pairs that you mix with
        rct_pointV pseudoOuts; //C - for simple rct
        std::vector<ecdhTuple> ecdhInfo;
        ctrct_pointV outPk;
        amount_t txnFee; // contains b

        template<bool W, template <bool> class Archive>
        bool serialize_rctsig_base(Archive<W> &ar, size_t inputs, size_t outputs)
        {
          FIELD(type)
          if (type == RCTTypeNull)
            return ar.stream().good();
          if (type != RCTTypeCLSAG)
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
            {
              ar.begin_object();
              if (!typename Archive<W>::is_saving())
                ecdhInfo[i].amount = {};
              crypto::hash8 &amount = (crypto::hash8&)ecdhInfo[i].amount;
              FIELD(amount);
              ar.end_object();
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
        std::vector<Bulletproof> bulletproofs;
        std::vector<clsag> CLSAGs;
        rct_pointV pseudoOuts; //C - for simple rct

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
          if (type != RCTTypeCLSAG)
            return false;
          {
            uint32_t nbp = bulletproofs.size();
            VARINT_FIELD(nbp)
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
          FIELD(bulletproofs)
          FIELD(CLSAGs)
          FIELD(pseudoOuts)
        END_SERIALIZE()
    };

    struct rctSig: public rctSigBase {
        rctSigPrunable p;

        rct_pointV& get_pseudo_outs()
        {
          return type == RCTTypeCLSAG ? p.pseudoOuts : pseudoOuts;
        }

        rct_pointV const& get_pseudo_outs() const
        {
          return type == RCTTypeCLSAG ? p.pseudoOuts : pseudoOuts;
        }

        BEGIN_SERIALIZE_OBJECT()
          FIELDS((rctSigBase&)*this)
          FIELD(p)
        END_SERIALIZE()
    };

    //various conversions

    //32 byte rct_point to uint long long
    // if the rct_point holds a value > 2^64
    // then the value in the first 8 bytes is returned
    amount_t scalar_to_int(const scalar &in);

    //uint long long to 32 byte key
    scalar int_to_scalar(const amount_t in);

    inline const rct::scalar &sk2scalar(const crypto::secret_key &sk) { return (const rct::scalar&)sk; }
    inline const crypto::secret_key &scalar2sk(const rct::scalar&k) { return (const crypto::secret_key&)k; }

    inline const rct::rct_point &pk2rct(const crypto::public_key &pk) { return (const rct::rct_point&)pk; }
    inline const rct::rct_point &ki2rct(const crypto::key_image &ki) { return (const rct::rct_point&)ki; }
    inline const rct::rct_point &p2rct(const crypto::ec_point &p) { return (const rct::rct_point&)p; }

    inline const crypto::public_key &rct2pk(const rct::rct_point &k) { return (const crypto::public_key&)k; }
    inline const crypto::secret_key &unsafe_rct2sk(const rct::rct_point &k) { return (const crypto::secret_key&)k; }
    inline const crypto::key_image &rct2ki(const rct::rct_point &k) { return (const crypto::key_image&)k; }
    inline const crypto::hash &rct2hash(const rct::rct_point &k) { return (const crypto::hash&)k; }

    inline const rct::scalar &s2s(const crypto::ec_scalar &s) { return (const rct::scalar&)s; }

    inline const rct::inv8V to_inv8V(const rct_pointS &xs) {
      inv8V ys;
      std::transform
        (
        xs.begin()
        , xs.end()
        , std::back_inserter(ys)
        , [](const auto& x) { return x; }
        );

      return ys;
    }


    // unsafe
    inline const rct::rct_point &unsafe_hash2rct(const crypto::hash &h) { return (const rct::rct_point&)h; }
    inline const rct::rct_point &unsafe_d2rct(const crypto::crypto_data &p) { return (const rct::rct_point&)p; }
}



namespace rct {
inline std::ostream &operator <<(std::ostream &o, const rct::rct_point &v) {
  epee::hex::append_decode_formatted(o, epee::pod_to_span(v)); return o;
}
}


namespace std
{
  template<> struct hash<rct::rct_point> { std::size_t operator()(const rct::rct_point &k) const { return reinterpret_cast<const std::size_t&>(k); } };
}

BLOB_SERIALIZER(rct::rct_point);
BLOB_SERIALIZER(rct::inv8);
BLOB_SERIALIZER(rct::ctkey);
BLOB_SERIALIZER(rct::scalar);
BLOB_SERIALIZER(rct::pri_ctkey);

BLOB_SERIALIZER(crypto::ec_scalar_unnormalized);
