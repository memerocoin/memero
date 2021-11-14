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
  using rct_point = crypto::ec_point;
  using rct_scalar = crypto::ec_scalar;

  using inv8 = crypto::ec_point_unsafe;
  using reconstructed_point = rct::rct_point;


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

  const rct::inv8V to_inv8V(const rct_pointS xs);


  struct output_public_data {
    rct_point output_spend_pk;
    rct_point commit;
  };

  struct output_commit {
    rct_point commit;
  };

  using output_public_dataV = std::vector<output_public_data>;
  using output_public_dataM = std::vector<output_public_dataV>; //matrix of keys (indexed by column first)
  using output_public_dataS = std::span<const output_public_data>;

  //data for passing the amount to the receiver secretly
  struct ecdh_encrypted_data {
    uint64_t masked_amount;
  };

  //containers for representing amounts
  using amount_t = uint64_t;

  // CLSAG signature
  struct clsag_unsafe {
    std::vector<crypto::ec_scalar_unnormalized> s; // scalars
    crypto::ec_scalar_unnormalized c1;

    reconstructed_point signer_pk_image; // signing key image
    inv8 signer_pk_image_from_blinding_surplus; // commitment key image

    BEGIN_SERIALIZE_OBJECT()
      FIELD(s)
      FIELD(c1)
      // FIELD(I) - not serialized, it can be reconstructed
      FIELD(signer_pk_image_from_blinding_surplus)
    END_SERIALIZE()
  };

  struct clsag {
    rct_scalarV s; // scalars
    rct_scalar c1;
    rct_point signer_pk_image; // signing key image
    rct_point signer_pk_image_from_blinding_surplus; // commitment key image
  };

  std::optional<clsag> maybeSafeCLSAG(const clsag_unsafe clsag);
  clsag_unsafe toUnsafeCLSAG(const clsag clsag);

  struct Bulletproof_unsafe
  {
    std::vector<reconstructed_point> commits;
    rct::inv8 A, S;
    rct::inv8 T1, T2;
    crypto::ec_scalar_unnormalized taux, mu;
    rct::inv8V L, R;
    crypto::ec_scalar_unnormalized a, b, t;

    // bool operator==(const Bulletproof_unsafe&) const = default;

    BEGIN_SERIALIZE_OBJECT()
      // Commitments aren't saved, they're restored via output_commits
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

  using LR_V = std::vector<std::pair<rct_point, rct_point>>;

  struct Bulletproof
  {
    rct::rct_pointV commits;
    rct::rct_point A, S;
    rct::rct_point T1, T2;
    rct::rct_scalar taux, mu;
    LR_V LR;
    rct::rct_scalar a, b, t;
  };

  std::optional<LR_V> zipLR(const rct_pointV L, const rct_pointV R);

  std::pair<rct_pointV, rct_pointV>
  splitLR(const std::span<const std::pair<rct_point, rct_point>> LR);
  
  std::optional<Bulletproof> maybeSafeBulletproof(const Bulletproof_unsafe proof);
  Bulletproof_unsafe toUnsafeBulletproof(const Bulletproof proof);

  bool is_bulletproof_structure_valid(const Bulletproof_unsafe &proof);
  size_t n_bulletproof_amounts(const Bulletproof_unsafe &proof);
  size_t n_bulletproof_max_amounts(const Bulletproof_unsafe &proof);

  //A container to hold all signatures necessary for RingCT
  // rangeSigs holds all the rangeproof data of a transaction
  // MG holds the MLSAG signature of a transaction
  // decoys holds all the public keypairs (P, C) for a transaction
  // ecdh holds an encoded blinding_factor / amount to be passed to each receiver
  // output_commits contains public keypairs which are destinations (P, C),
  //  P = address, C = commitment to amount
  enum {
    RCTTypeNull = 0,
    RCTTypeCLSAG = 5,
  };

  struct rctDataEssential {
    uint8_t type;
    crypto::hash message;
    output_public_dataM decoys; //the set of all pubkeys / copy
    //pairs that you mix with
    // rct_pointV unusedPoints;
    std::vector<ecdh_encrypted_data> ecdh;

    // WARNING, needs checking when parsing
    std::vector<output_commit> output_commits;

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
      // FIELD(decoys) - not serialized, it can be reconstructed
      ar.tag("ecdh_encrypted_data");
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

      ar.tag("output_commits");
      ar.begin_array();
      PREPARE_CUSTOM_VECTOR_SERIALIZATION(outputs, output_commits);
      if (output_commits.size() != outputs)
        return false;
      for (size_t i = 0; i < outputs; ++i)
      {
        FIELDS(output_commits[i].commit)
        if (!typename Archive<W>::is_saving()) {
          if (!is_safe_point(output_commits[i].commit)) return false;
        }
        if (outputs - i > 1)
          ar.delimit_array();
      }
      ar.end_array();
      return ar.stream().good();
    }
  };

  struct rctDataPrunable {
    std::vector<Bulletproof_unsafe> bulletproofs;
    std::vector<clsag_unsafe> CLSAGs;

    // WARNING, needs checking when parsing
    rct_pointV pseudo_input_commits; //C - for simple rct

    // when changing this function, update cryptonote::get_pruned_transaction_weight
    template<bool W, template <bool> class Archive>
    bool serialize_ringct_prunable
    (Archive<W> &ar, uint8_t type, size_t inputs, size_t outputs, size_t mixin)
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
        uint32_t number_of_range_proofs = bulletproofs.size();
        VARINT_FIELD(number_of_range_proofs)
        ar.tag("range_proofs");
        ar.begin_array();
        if (number_of_range_proofs > outputs)
          return false;
        if (number_of_range_proofs != 1)
          return false;
        PREPARE_CUSTOM_VECTOR_SERIALIZATION(number_of_range_proofs, bulletproofs);
        for (size_t i = 0; i < number_of_range_proofs; ++i)
        {
          FIELDS(bulletproofs[i])
          if (number_of_range_proofs - i > 1)
            ar.delimit_array();
        }
        const auto proof = bulletproofs.front();
        if (n_bulletproof_max_amounts(proof) < outputs)
          return false;
        if (!is_bulletproof_structure_valid(proof))
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
          FIELDS(CLSAGs[i].signer_pk_image_from_blinding_surplus)
          ar.end_object();

          if (inputs - i > 1)
              ar.delimit_array();
        }

        ar.end_array();
      }

      {
        ar.tag("pseudo_input_commits");
        ar.begin_array();
        PREPARE_CUSTOM_VECTOR_SERIALIZATION(inputs, pseudo_input_commits);
        if (pseudo_input_commits.size() != inputs)
          return false;
        for (size_t i = 0; i < inputs; ++i)
        {
          FIELDS(pseudo_input_commits[i])
          if (!typename Archive<W>::is_saving()) {
            if (!is_safe_point(pseudo_input_commits[i])) return false;
          }
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
BLOB_SERIALIZER(rct::output_public_data);
BLOB_SERIALIZER(rct::output_commit);
BLOB_SERIALIZER(rct::rct_scalar);
BLOB_SERIALIZER(rct::ecdh_encrypted_data);
BLOB_SERIALIZER(crypto::ec_scalar_unnormalized);
