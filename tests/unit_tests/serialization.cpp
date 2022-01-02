// Copyright (c) 2014-2020, The Monero Project
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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "unit_tests_utils.h"

#include "cryptonote/basic/functional/base.hpp"
#include "cryptonote/basic/functional/base.hpp"

#include "tools/serialization/binary_archive.h"
#include "tools/serialization/json_archive.h"
#include "tools/serialization/variant.h"
#include "tools/serialization/containers.h"
#include "tools/serialization/binary_utils.h"

#include "wallet/logic/type/wallet.hpp"

#include "gtest/gtest.h"

#include <boost/foreach.hpp>

#include <cstring>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <vector>



using namespace std;
using namespace crypto;
using namespace wallet::logic::type::wallet;

namespace rct {

  struct ct_secret_key {
    rct_scalar addr;
    rct_scalar blinding_factor;
  };

  using ct_secret_keyV = std::vector<ct_secret_key>;
  using ct_secret_keyS = std::span<const ct_secret_key>;

  std::pair<rct_scalar, crypto::ec_point> skpkGen() {
    const rct_scalar sk = crypto::randomScalar();
    return std::make_pair(sk, G_(sk));
  }

}

struct Struct
{
  int32_t a;
  int32_t b;
  char blob[8];
};

template <class Archive>
struct serializer<Archive, Struct>
{
  static bool serialize(Archive &ar, Struct &s) {
    ar.begin_object();
    ar.tag("a");
    ar.serialize_int(s.a);
    ar.tag("b");
    ar.serialize_int(s.b);
    ar.tag("blob");
    ar.serialize_blob(s.blob, sizeof(s.blob));
    ar.end_object();
    return true;
  }
};

struct Struct1
{
  vector<boost::variant<Struct, int32_t>> si;
  vector<int16_t> vi;

  BEGIN_SERIALIZE_OBJECT()
    FIELD(si)
    FIELD(vi)
  END_SERIALIZE()
  /*template <bool W, template <bool> class Archive>
  bool do_serialize(Archive<W> &ar)
  {
    ar.begin_object();
    ar.tag("si");
    ::do_serialize(ar, si);
    ar.tag("vi");
    ::do_serialize(ar, vi);
    ar.end_object();
  }*/
};

struct Blob
{
  uint64_t a;
  uint32_t b;

  bool operator==(const Blob& rhs) const
  {
    return a == rhs.a;
  }
};

VARIANT_TAG(binary_archive, Struct, 0xe0);
VARIANT_TAG(binary_archive, int, 0xe1);
VARIANT_TAG(json_archive, Struct, "struct");
VARIANT_TAG(json_archive, int, "int");

BLOB_SERIALIZER(Blob);

bool try_parse(const string &blob)
{
  Struct1 s1;
  return serialization::parse_binary(blob, s1);
}


//initializes a rct_scalar matrix;
//first parameter is rows,
//second is columns
std::vector<rct::scalarV> rct_scalarMInit(size_t rows, size_t cols) {
  std::vector<rct::scalarV> rv(cols);
  size_t i = 0;
  for (i = 0 ; i < cols ; i++) {
    rv[i] = rct::scalarV(rows);
  }
  return rv;
}

crypto::ec_point pkGen() {
  return rct::skpkGen().second;
}

namespace rct {
//generates a <secret , public> / Pedersen commitment to the amount
std::pair<ct_secret_key, rct::output_public_data> ctskpkGen(amount_t amount) {
  const auto [addr_sk, addr_pk] = skpkGen();
  const auto [blinding_factor_sk, blinding_factor_pk] = skpkGen();

  const rct_scalar am = int_to_scalar(amount);
  const crypto::ec_point bH = H_(am);

  return
    {
      {addr_sk, blinding_factor_sk}
      , {addr_pk, blinding_factor_pk + bH}
    };
}
}


TEST(Serialization, BinaryArchiveInts) {
  uint64_t x = 0xff00000000, x1;

  ostringstream oss;
  binary_archive<true> oar(oss);
  oar.serialize_int(x);
  ASSERT_TRUE(oss.good());
  ASSERT_EQ(8, oss.str().size());
  ASSERT_EQ(string("\0\0\0\0\xff\0\0\0", 8), oss.str());

  istringstream iss(oss.str());
  binary_archive<false> iar(iss);
  iar.serialize_int(x1);
  ASSERT_EQ(8, iss.tellg());
  ASSERT_TRUE(iss.good());

  ASSERT_EQ(x, x1);
}

TEST(Serialization, BinaryArchiveVarInts) {
  uint64_t x = 0xff00000000, x1;

  ostringstream oss;
  binary_archive<true> oar(oss);
  oar.serialize_varint(x);
  ASSERT_TRUE(oss.good());
  ASSERT_EQ(6, oss.str().size());
  ASSERT_EQ(string("\x80\x80\x80\x80\xF0\x1F", 6), oss.str());

  istringstream iss(oss.str());
  binary_archive<false> iar(iss);
  iar.serialize_varint(x1);
  ASSERT_TRUE(iss.good());
  ASSERT_EQ(x, x1);
}

TEST(Serialization, Test1) {
  ostringstream str;
  binary_archive<true> ar(str);

  Struct1 s1;
  s1.si.push_back(0);
  {
    Struct s;
    s.a = 5;
    s.b = 65539;
    std::memcpy(s.blob, "12345678", 8);
    s1.si.push_back(s);
  }
  s1.si.push_back(1);
  s1.vi.push_back(10);
  s1.vi.push_back(22);

  string blob;
  ASSERT_TRUE(serialization::dump_binary(s1, blob));
  ASSERT_TRUE(try_parse(blob));

  ASSERT_EQ('\xE0', blob[6]);
  blob[6] = '\xE1';
  ASSERT_FALSE(try_parse(blob));
  blob[6] = '\xE2';
  ASSERT_FALSE(try_parse(blob));
}

TEST(Serialization, Overflow) {
  Blob x = { 0xff00000000 };
  Blob x1;

  string blob;
  ASSERT_TRUE(serialization::dump_binary(x, blob));
  ASSERT_EQ(sizeof(Blob), blob.size());

  ASSERT_TRUE(serialization::parse_binary(blob, x1));
  ASSERT_EQ(x, x1);

  vector<Blob> bigvector;
  ASSERT_FALSE(serialization::parse_binary(blob, bigvector));
  ASSERT_EQ(0, bigvector.size());
}

TEST(Serialization, serializes_vector_uint64_as_varint)
{
  std::vector<uint64_t> v;
  string blob;

  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(1, blob.size());

  // +1 byte
  v.push_back(0);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(2, blob.size());

  // +1 byte
  v.push_back(1);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(3, blob.size());

  // +2 bytes
  v.push_back(0x80);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(5, blob.size());

  // +2 bytes
  v.push_back(0xFF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(7, blob.size());

  // +2 bytes
  v.push_back(0x3FFF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(9, blob.size());

  // +3 bytes
  v.push_back(0x40FF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(12, blob.size());

  // +10 bytes
  v.push_back(0xFFFFFFFFFFFFFFFF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(22, blob.size());
}

TEST(Serialization, serializes_vector_int64_as_fixed_int)
{
  std::vector<int64_t> v;
  string blob;

  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(1, blob.size());

  // +8 bytes
  v.push_back(0);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(9, blob.size());

  // +8 bytes
  v.push_back(1);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(17, blob.size());

  // +8 bytes
  v.push_back(0x80);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(25, blob.size());

  // +8 bytes
  v.push_back(0xFF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(33, blob.size());

  // +8 bytes
  v.push_back(0x3FFF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(41, blob.size());

  // +8 bytes
  v.push_back(0x40FF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(49, blob.size());

  // +8 bytes
  v.push_back(0xFFFFFFFFFFFFFFFF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(57, blob.size());
}

namespace
{
  template<typename T>
  std::vector<T> linearize_vector2(const std::vector< std::vector<T> >& vec_vec)
  {
    std::vector<T> res;
    for(const auto& vec: vec_vec)
    {
      res.insert(res.end(), vec.begin(), vec.end());
    }
    return res;
  }
}

TEST(Serialization, serializes_transacion_signatures_correctly)
{
  using namespace cryptonote;

  transaction tx;
  transaction tx1;
  string blob;

  // Empty tx
  ASSERT_TRUE(serialization::dump_binary(tx, blob));
  ASSERT_EQ(5, blob.size()); // 5 bytes + 0 bytes extra + 0 bytes signatures
  ASSERT_TRUE(serialization::parse_binary(blob, tx1));
  ASSERT_EQ(tx, tx1);

  // Miner tx without signatures
  txin_gen txin_gen1;
  txin_gen1.height = 0;
  tx = {};
  tx.vin.push_back(txin_gen1);
  ASSERT_TRUE(serialization::dump_binary(tx, blob));
  ASSERT_EQ(7, blob.size()); // 5 bytes + 2 bytes vin[0] + 0 bytes extra + 0 bytes signatures
  ASSERT_TRUE(serialization::parse_binary(blob, tx1));
  ASSERT_EQ(tx, tx1);
}

TEST(Serialization, serializes_ringct_types)
{
  string blob;
  rct::rct_scalar key0, key1;
  rct::scalarV keyv0, keyv1;
  std::vector<rct::scalarV> keym0, keym1;
  rct::output_public_data output_public_data0, output_public_data1;
  rct::output_public_dataV output_public_datav0, output_public_datav1;
  rct::output_public_dataM output_public_datam0, output_public_datam1;
  rct::ecdh_encrypted_data_t ecdh0, ecdh1;
  rct::clsag_unsafe clsag0, clsag1;
  rct::rctData s0, s1;
  cryptonote::transaction tx0, tx1;

  key0 = crypto::randomScalar();
  ASSERT_TRUE(serialization::dump_binary(key0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, key1));
  ASSERT_TRUE(key0 == key1);

  keyv0 = crypto::randomScalars(30);
  for (size_t n = 0; n < keyv0.size(); ++n)
    keyv0[n] = crypto::randomScalar();
  ASSERT_TRUE(serialization::dump_binary(keyv0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, keyv1));
  ASSERT_TRUE(keyv0.size() == keyv1.size());
  for (size_t n = 0; n < keyv0.size(); ++n)
  {
    ASSERT_TRUE(keyv0[n] == keyv1[n]);
  }

  keym0 = rct_scalarMInit(9, 12);

  for (size_t n = 0; n < keym0.size(); ++n)
    for (size_t i = 0; i < keym0[n].size(); ++i)
      keym0[n][i] = crypto::randomScalar();

  ASSERT_TRUE(serialization::dump_binary(keym0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, keym1));
  ASSERT_TRUE(keym0.size() == keym1.size());

  for (size_t n = 0; n < keym0.size(); ++n)
  {
    ASSERT_TRUE(keym0[n].size() == keym1[n].size());
    for (size_t i = 0; i < keym0[n].size(); ++i)
    {
      ASSERT_TRUE(keym0[n][i] == keym1[n][i]);
    }
  }

  output_public_data0.output_public_key = pkGen();
  output_public_data0.commit = pkGen();

  ASSERT_TRUE(serialization::dump_binary(output_public_data0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, output_public_data1));
  ASSERT_TRUE(!memcmp(&output_public_data0, &output_public_data1, sizeof(output_public_data0)));

  output_public_datav0 = std::vector<rct::output_public_data>(14);
  for (size_t n = 0; n < output_public_datav0.size(); ++n) {
    output_public_datav0[n].output_public_key = pkGen();
    output_public_datav0[n].commit = pkGen();
  }

  ASSERT_TRUE(serialization::dump_binary(output_public_datav0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, output_public_datav1));
  ASSERT_TRUE(output_public_datav0.size() == output_public_datav1.size());
  for (size_t n = 0; n < output_public_datav0.size(); ++n)
  {
    ASSERT_TRUE(!memcmp(&output_public_datav0[n], &output_public_datav1[n], sizeof(output_public_datav0[n])));
  }

  output_public_datam0 = std::vector<rct::output_public_dataV>(9);
  for (size_t n = 0; n < output_public_datam0.size(); ++n)
  {
    output_public_datam0[n] = std::vector<rct::output_public_data>(11);
    for (size_t i = 0; i < output_public_datam0[n].size(); ++i) {
      output_public_datam0[n][i].output_public_key = pkGen();
      output_public_datam0[n][i].commit = pkGen();
    }
  }
  ASSERT_TRUE(serialization::dump_binary(output_public_datam0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, output_public_datam1));
  ASSERT_TRUE(output_public_datam0.size() == output_public_datam1.size());
  for (size_t n = 0; n < output_public_datam0.size(); ++n)
  {
    ASSERT_TRUE(output_public_datam0[n].size() == output_public_datam1[n].size());
    for (size_t i = 0; i < output_public_datam0.size(); ++i)
    {
      ASSERT_TRUE(!memcmp(&output_public_datam0[n][i], &output_public_datam1[n][i], sizeof(output_public_datam0[n][i])));
    }
  }

  ecdh0.masked_amount = crypto::scalar_to_int(crypto::randomScalar());
  ASSERT_TRUE(serialization::dump_binary(ecdh0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, ecdh1));
  ASSERT_TRUE(!memcmp(&ecdh0.masked_amount, &ecdh1.masked_amount, sizeof(ecdh0.masked_amount)));

  // create a full rct signature to use its innards
  vector<uint64_t> inamounts;
  rct::ct_secret_keyV sc;
  rct::output_public_dataV pc;
  rct::ct_secret_key sctmp;
  rct::output_public_data pctmp;
  inamounts.push_back(6000);
  tie(sctmp, pctmp) = rct::ctskpkGen(inamounts.back());
  sc.push_back(sctmp);
  pc.push_back(pctmp);
  inamounts.push_back(7000);
  tie(sctmp, pctmp) = rct::ctskpkGen(inamounts.back());
  sc.push_back(sctmp);
  pc.push_back(pctmp);
  vector<uint64_t> amounts;
  rct::scalarV output_shared_secrets_hashed_by_index;
  //add output 500
  amounts.push_back(500);
  output_shared_secrets_hashed_by_index.push_back(rct::hash_to_scalar({}));
  rct::pointV destinations;
  rct::rct_scalar Sk;
  crypto::ec_point Pk;
  std::tie(Sk, Pk) = rct::skpkGen();
  destinations.push_back(Pk);
  //add output for 12500
  amounts.push_back(12500);
  output_shared_secrets_hashed_by_index.push_back(rct::hash_to_scalar({}));
  std::tie(Sk, Pk) = rct::skpkGen();
  destinations.push_back(Pk);

  ASSERT_TRUE(serialization::dump_binary(clsag0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, clsag1));
  ASSERT_TRUE(clsag0.s.size() == clsag1.s.size());

  for (size_t n = 0; n < clsag0.s.size(); ++n)
  {
    ASSERT_TRUE(clsag0.s[n] == clsag1.s[n]);
  }
  ASSERT_TRUE(clsag0.c1 == clsag1.c1);
  // I is not serialized, they are meant to be reconstructed
  ASSERT_TRUE(clsag0.blinding_factor_surplus_key_image == clsag1.blinding_factor_surplus_key_image);
}

BLOB_SERIALIZER(rct::ct_secret_key);
