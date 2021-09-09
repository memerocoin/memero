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

#include "math/crypto/functional/key.hpp"

#include "tools/serialization/containers.h"

#include <sodium/crypto_verify_32.h>

#include <span>


//Namespace specifically for ring ct code
namespace rct {
    // Can contain a secret or public key
    //  similar to secret_key / public_key of crypto-ops,
    //  but uses unsigned chars,
    //  also includes an operator for accessing the i'th byte.
    struct rct_scalar;
    struct rct_point : crypto::ec_point {
      rct_point operator+(const rct_point& y) const;
      rct_point operator-(const rct_point& y) const;
      rct_point operator^(const rct_scalar& x) const;
      bool operator<(const rct_point& y) const;
    };


    using inv8 = crypto::ec_point_unsafe;
    using reconstructed_point = rct::rct_point;


    struct rct_scalar : crypto::ec_scalar {
      rct_scalar operator+(const rct_scalar& y) const;
      rct_scalar operator-(const rct_scalar& y) const;
      rct_scalar operator*(const rct_scalar& y) const;
    };

    using rct_pointV = std::vector<rct_point>;
    using rct_pointM = std::vector<rct_pointV>;
    using rct_pointS = std::span<const rct_point>;
    using rct_pointL = std::list<const rct_point>;

    using rct_scalarV = std::vector<rct_scalar>;
    using rct_scalarM = std::vector<rct_scalarV>;
    using rct_scalarS = std::span<const rct_scalar>;
    using rct_scalarL = std::list<rct_scalar>;

    using inv8V = std::vector<inv8>;
    using inv8S = std::span<const inv8>;
    using inv8L = std::list<const inv8>;


    // containers For CT operations
    // "dest": addr * G
    // "amount_commit": bliding_factor * G + amount * H
    // f : (ct_secret_key, uint64_t) -> ct_public_key
    struct ct_public_key {
        rct_point dest;
        rct_point amount_commit;
    };

    using ct_public_keyV = std::vector<ct_public_key>;
    using ct_public_keyM = std::vector<ct_public_keyV>; //matrix of keys (indexed by column first)
    using ct_public_keyS = std::span<const ct_public_key>;

    // addr is the secret key
    // blinding_factor is for committed value
    struct ct_secret_key {
      rct_scalar addr;
      rct_scalar blinding_factor;
    };

    using ct_secret_keyV = std::vector<ct_secret_key>;
    using ct_secret_keyS = std::span<const ct_secret_key>;

    //data for passing the amount to the receiver secretly
    struct ecdh_encrypted_data {
        crypto::ec_scalar_unnormalized masked_amount;
    };

    //containers for representing amounts
    using amount_t = uint64_t;

    // CLSAG signature
    struct clsag {
        std::vector<crypto::ec_scalar_unnormalized> s; // scalars
        crypto::ec_scalar_unnormalized c1;

        reconstructed_point I; // signing key image
        inv8 D; // commitment key image

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
      rct::rct_scalar taux;
      rct::rct_scalar mu;
      rct::inv8V L, R;
      rct::rct_scalar a, b, t;

      // bool operator==(const Bulletproof&) const = default;

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
    // ecdh holds an encoded blinding_factor / amount to be passed to each receiver
    // outPk contains public keypairs which are destinations (P, C),
    //  P = address, C = commitment to amount
    enum {
      RCTTypeNull = 0,
      RCTTypeCLSAG = 5,
    };

    struct rctDataEssential {
        uint8_t type;
        crypto::hash message;
        ct_public_keyM mixRing; //the set of all pubkeys / copy
        //pairs that you mix with
        // rct_pointV unusedPoints;
        std::vector<ecdh_encrypted_data> ecdh;
        ct_public_keyV outPk;
        amount_t fee; // contains b

        template<bool W, template <bool> class Archive>
        bool serialize_rctsig_base(Archive<W> &ar, size_t inputs, size_t outputs)
        {
          FIELD(type)
          if (type == RCTTypeNull)
            return ar.stream().good();
          if (type != RCTTypeCLSAG)
            return false;
          VARINT_FIELD(fee)
          // inputs/outputs not saved, only here for serialization help
          // FIELD(message) - not serialized, it can be reconstructed
          // FIELD(mixRing) - not serialized, it can be reconstructed
          ar.tag("ecdh");
          ar.begin_array();
          PREPARE_CUSTOM_VECTOR_SERIALIZATION(outputs, ecdh);
          if (ecdh.size() != outputs)
            return false;
          for (size_t i = 0; i < outputs; ++i)
          {
            {
              ar.begin_object();
              if (!typename Archive<W>::is_saving())
                ecdh[i].masked_amount = {};
              crypto::hash8 &masked_amount = (crypto::hash8&)ecdh[i].masked_amount;
              FIELD(masked_amount);
              ar.end_object();
            }
            if (outputs - i > 1)
              ar.delimit_array();
          }
          ar.end_array();

          ar.tag("amount_commits");
          ar.begin_array();
          PREPARE_CUSTOM_VECTOR_SERIALIZATION(outputs, outPk);
          if (outPk.size() != outputs)
            return false;
          for (size_t i = 0; i < outputs; ++i)
          {
            FIELDS(outPk[i].amount_commit)
            if (outputs - i > 1)
              ar.delimit_array();
          }
          ar.end_array();
          return ar.stream().good();
        }
    };

    struct rctDataPrunable {
        std::vector<Bulletproof> bulletproofs;
        std::vector<clsag> CLSAGs;
        rct_pointV pseudo_amount_commits; //C - for simple rct

        // when changing this function, update cryptonote::get_pruned_transaction_weight
        template<bool W, template <bool> class Archive>
        bool serialize_ringct_prunable(Archive<W> &ar, uint8_t type, size_t inputs, size_t outputs, size_t mixin)
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
            ar.tag("range_proofs");
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
            ar.tag("ring_signatures");
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
            ar.tag("pseudo_amount_commits");
            ar.begin_array();
            PREPARE_CUSTOM_VECTOR_SERIALIZATION(inputs, pseudo_amount_commits);
            if (pseudo_amount_commits.size() != inputs)
              return false;
            for (size_t i = 0; i < inputs; ++i)
            {
              FIELDS(pseudo_amount_commits[i])
              if (inputs - i > 1)
                ar.delimit_array();
            }
            ar.end_array();
          }
          return ar.stream().good();
        }
    };

    struct rctData: public rctDataEssential {
        rctDataPrunable p;
    };

    //various conversions

    //32 byte rct_point to uint long long
    // if the rct_point holds a value > 2^64
    // then the value in the first 8 bytes is returned
    amount_t scalar_to_int(const rct_scalar &in);

    //uint long long to 32 byte key
    rct_scalar int_to_scalar(const amount_t in);

    inline const rct::rct_scalar &sk2rct_s(const crypto::secret_key &sk) { return (const rct::rct_scalar&)sk; }
    inline const crypto::secret_key &rct_s2sk(const rct::rct_scalar&k) { return (const crypto::secret_key&)k; }

    inline const rct::rct_point &pk2rct_p(const crypto::public_key &pk) { return (const rct::rct_point&)pk; }
    inline const rct::rct_point &ki2rct_p(const crypto::shared_secret_derived_public_key_image &ki) { return (const rct::rct_point&)ki; }
    inline const rct::rct_point &p2rct_p(const crypto::ec_point &p) { return (const rct::rct_point&)p; }

    inline const crypto::public_key &rct_p2pk(const rct::rct_point &k) { return (const crypto::public_key&)k; }
    inline const crypto::secret_key &unsafe_rct_p2sk(const rct::rct_point &k) { return (const crypto::secret_key&)k; }
    inline const crypto::shared_secret_derived_public_key_image &rct_p2ki(const rct::rct_point &k) { return (const crypto::shared_secret_derived_public_key_image&)k; }
    inline const crypto::hash &rct_p2hash(const rct::rct_point &k) { return (const crypto::hash&)k; }

    inline const rct::rct_scalar &s2s(const crypto::ec_scalar &s) { return (const rct::rct_scalar&)s; }

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
    inline const rct::rct_point &unsafe_hash2rct_p(const crypto::hash &h) { return (const rct::rct_point&)h; }
    inline const rct::rct_point &unsafe_d2rct_p(const crypto::crypto_data &p) { return (const rct::rct_point&)p; }
}


namespace std
{
  template<> struct hash<rct::rct_point>
  {
    std::size_t operator()(const rct::rct_point& x) const noexcept
    {
      boost::hash<std::array<uint8_t,32>> array_hash;
      return array_hash(x.data);
    }
  };
}

BLOB_SERIALIZER(rct::rct_point);
BLOB_SERIALIZER(rct::inv8);
BLOB_SERIALIZER(rct::ct_public_key);
BLOB_SERIALIZER(rct::rct_scalar);
BLOB_SERIALIZER(rct::ct_secret_key);
BLOB_SERIALIZER(rct::ecdh_encrypted_data);
BLOB_SERIALIZER(crypto::ec_scalar_unnormalized);
