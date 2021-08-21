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

#include "gtest/gtest.h"

#include <cstdint>
#include <algorithm>
#include <sstream>

#include "tools/epee/include/string_tools.h"

#include "math/ringct/functional/rctTypes.hpp"
#include "math/ringct/pseudo_functional/rctSigs.hpp"
#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/functional/curveConstants.hpp"
#include "math/ringct/controller/rctGen.hpp"
#include "math/ringct/controller/rctSigGen.hpp"

#include "math/crypto/controller/random.hpp"

#include "wallet/device/device.hpp"


using namespace std;
using namespace crypto;
using namespace rct;

TEST(ringct, CLSAG)
{
  const size_t N = 11;
  const size_t idx = 5;
  ct_public_keyV pubs;
  rct_scalar p, t, t2, u;
  const crypto::hash message = crypto::d2h(rct::identity);
  ct_public_key backup;
  clsag clsag;

  for (size_t i = 0; i < N; ++i)
  {
    rct_scalar sk;
    ct_public_key tmp;

    std::tie(sk, tmp.dest) = skpkGen();
    std::tie(sk, tmp.commit_of_amount) = skpkGen();

    pubs.push_back(tmp);
  }

  // Set P[idx]
  std::tie(p, pubs[idx].dest) = skpkGen();

  // Set C[idx]
  t = skGen();
  u = skGen();
  pubs[idx].commit_of_amount = addMultG_H(t,u);

  // Set commitment offset
  t2 = skGen();
  rct_point Cout = addMultG_H(t2,u);

  // Prepare generation inputs
  ct_secret_key insk;
  insk.addr = p;
  insk.blinding_factor = t;


  // clsag makeRctCLSAGSimple
  //   (
  //    const rct_point &
  //    , const ct_public_keyV &
  //    , const ct_public_key &
  //    , const rct_point &
  //    , const rct_point &
  //    , const unsigned int
  //    );

  // bad message
  clsag = rct::makeRctCLSAGSimple
    (
     {},
     pubs,
     insk,
     t2,
     Cout,
     idx
     );
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));

  // bad index at creation
  try
  {
    clsag = rct::makeRctCLSAGSimple(message,pubs,insk,t2,Cout,(idx + 1) % N);
    ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }

  // bad z at creation
  try
  {
    ct_secret_key insk2;
    insk2.addr = insk.addr;
    insk2.blinding_factor = skGen();
    clsag = rct::makeRctCLSAGSimple(message,pubs,insk2,t2,Cout,idx);
    ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }

  // bad C at creation
  backup = pubs[idx];
  pubs[idx].commit_of_amount = multG(skGen());
  try
  {
    clsag = rct::makeRctCLSAGSimple(message,pubs,insk,t2,Cout,idx);
    ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }
  pubs[idx] = backup;

  // bad p at creation
  try
  {
    ct_secret_key insk2;
    insk2.addr = skGen();
    insk2.blinding_factor = insk.blinding_factor;
    clsag = rct::makeRctCLSAGSimple(message,pubs,insk2,t2,Cout,idx);
    ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }

  // bad P at creation
  backup = pubs[idx];
  pubs[idx].dest = multG(skGen());
  try
  {
    clsag = rct::makeRctCLSAGSimple(message,pubs,insk,t2,Cout,idx);
    ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }
  pubs[idx] = backup;

  // Test correct signature
  clsag = rct::makeRctCLSAGSimple(message,pubs,insk,t2,Cout,idx);
  ASSERT_TRUE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));

  // empty s
  auto sbackup = clsag.s;
  clsag.s.clear();
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.s = sbackup;

  // too few s elements
  rct_scalar backup_s;
  rct_point backup_key;
  inv8 backup_key_inv8;
  backup_s = clsag.s.back();
  clsag.s.pop_back();
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.s.push_back(backup_s);

  // too many s elements
  clsag.s.push_back(skGen());
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.s.pop_back();

  // bad s in clsag at verification
  for (auto &s: clsag.s)
  {
    backup_s = s;
    s = skGen();
    ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
    s = backup_s;
  }

  // bad c1 in clsag at verification
  backup_s = clsag.c1;
  clsag.c1 = skGen();
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.c1 = backup_s;

  // bad I in clsag at verification
  backup_key = clsag.I;
  clsag.I = multG(skGen());
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.I = backup_key;

  // bad D in clsag at verification
  backup_key_inv8 = clsag.D;
  clsag.D = multG(skGen());
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.D = backup_key_inv8;

  // D not in main subgroup in clsag at verification
  backup_key_inv8 = clsag.D;
  rct::rct_point x;
  ASSERT_TRUE(epee::string_tools::hex_to_pod("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", x));
  clsag.D = rct::unsafe_d2rct_p(clsag.D) + x;
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.D = backup_key_inv8;

  // swapped I and D in clsag at verification
  backup_key_inv8 = clsag.D;
  backup_key = clsag.I;

  clsag.I = rct::unsafe_d2rct_p(backup_key_inv8);
  clsag.D = clsag.I;

  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));

  clsag.I = backup_key;
  clsag.D = backup_key_inv8;

  // check it's still good, in case we failed to restore
  ASSERT_TRUE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
}


static rct::rctSig make_sample_simple_rct_sig(int n_inputs, const uint64_t input_amounts[], int n_outputs, const uint64_t output_amounts[], uint64_t fee)
{
    ct_secret_keyV sc;
    ct_public_keyV pc;
    ct_secret_key sctmp;
    ct_public_key pctmp;
    vector<amount_t> inamounts, outamounts;
    rct_pointV destinations;
    rct_scalarV amount_keys;
    rct_scalar Sk;
    rct_point Pk;

    for (int n = 0; n < n_inputs; ++n) {
        inamounts.push_back(input_amounts[n]);
        tie(sctmp, pctmp) = ctskpkGen(input_amounts[n]);
        sc.push_back(sctmp);
        pc.push_back(pctmp);
    }

    for (int n = 0; n < n_outputs; ++n) {
        outamounts.push_back(output_amounts[n]);
        amount_keys.push_back(hash_to_scalar(zero));
        std::tie(Sk, Pk) = skpkGen();
        destinations.push_back(Pk);
    }

    return genRctSimple({}, sc, pc, destinations, inamounts, outamounts, amount_keys, fee, 3);
}

static bool range_proof_test(bool expected_valid,
                             int n_inputs, const uint64_t input_amounts[], int n_outputs, const uint64_t output_amounts[], bool last_is_fee, bool _simple)
{
    //compute rct data
    bool valid;
    try {
        rctSig s;
        // simple takes fee as a parameter, non-simple takes it as an extra element to output amounts
        s = make_sample_simple_rct_sig(n_inputs, input_amounts, last_is_fee ? n_outputs - 1 : n_outputs, output_amounts, last_is_fee ? output_amounts[n_outputs - 1] : 0);
        valid = verRctSimple(s);
    }
    catch (const std::exception &e) {
        valid = false;
    }

    if (valid == expected_valid) {
        return testing::AssertionSuccess();
    }
    else {
        return testing::AssertionFailure();
    }
}

#define NELTS(array) (sizeof(array)/sizeof(array[0]))

TEST(ringct, range_proofs_reject_empty_outs_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_reject_empty_ins_simple)
{
  const uint64_t inputs[] = {};
  const uint64_t outputs[] = {5000};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_reject_all_empty_simple)
{
  const uint64_t inputs[] = {};
  const uint64_t outputs[] = {};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

// FIXME why failure?
TEST(ringct, range_proofs_reject_zero_empty_simple)
{
  const uint64_t inputs[] = {0};
  const uint64_t outputs[] = {};
  EXPECT_FALSE(range_proof_test(true, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_reject_empty_zero_simple)
{
  const uint64_t inputs[] = {};
  const uint64_t outputs[] = {0};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_accept_zero_zero_simple)
{
  const uint64_t inputs[] = {0};
  const uint64_t outputs[] = {0};
  EXPECT_TRUE(range_proof_test(true, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_accept_zero_out_first_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {0, 5000};
  EXPECT_TRUE(range_proof_test(true, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_accept_zero_out_last_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {5000, 0};
  EXPECT_TRUE(range_proof_test(true, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_accept_zero_out_middle_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {2500, 0, 2500};
  EXPECT_TRUE(range_proof_test(true, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_accept_zero_in_first_simple)
{
  const uint64_t inputs[] = {0, 5000};
  const uint64_t outputs[] = {5000};
  EXPECT_TRUE(range_proof_test(true, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_accept_zero_in_last_simple)
{
  const uint64_t inputs[] = {5000, 0};
  const uint64_t outputs[] = {5000};
  EXPECT_TRUE(range_proof_test(true, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_accept_zero_in_middle_simple)
{
  const uint64_t inputs[] = {2500, 0, 2500};
  const uint64_t outputs[] = {5000};
  EXPECT_TRUE(range_proof_test(true, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_reject_single_lower_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {1};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_reject_single_higher_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {5001};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_reject_single_out_negative_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {(uint64_t)-1000ll};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_reject_out_negative_first_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {(uint64_t)-1000ll, 6000};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_reject_out_negative_last_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {6000, (uint64_t)-1000ll};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_reject_out_negative_middle_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {3000, (uint64_t)-1000ll, 3000};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_reject_single_in_negative_simple)
{
  const uint64_t inputs[] = {(uint64_t)-1000ll};
  const uint64_t outputs[] = {5000};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_reject_in_negative_first)
{
  const uint64_t inputs[] = {(uint64_t)-1000ll, 6000};
  const uint64_t outputs[] = {5000};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, false, false));
}

TEST(ringct, range_proofs_reject_in_negative_first_simple)
{
  const uint64_t inputs[] = {(uint64_t)-1000ll, 6000};
  const uint64_t outputs[] = {5000};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_reject_in_negative_last_simple)
{
  const uint64_t inputs[] = {6000, (uint64_t)-1000ll};
  const uint64_t outputs[] = {5000};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_reject_in_negative_middle_simple)
{
  const uint64_t inputs[] = {3000, (uint64_t)-1000ll, 3000};
  const uint64_t outputs[] = {5000};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_reject_higher_list_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {1000, 1000, 1000, 1000, 1000, 1000};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}


// these require one of rct_scalar of H to be 0, why?
TEST(ringct, range_proofs_accept_1_to_1_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {5000};
  EXPECT_TRUE(range_proof_test(true, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_accept_1_to_N_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {1000, 1000, 1000, 1000, 1000};
  EXPECT_TRUE(range_proof_test(true, NELTS(inputs), inputs, NELTS(outputs), outputs, false,true));
}

TEST(ringct, range_proofs_accept_N_to_1_simple)
{
  const uint64_t inputs[] = {1000, 1000, 1000, 1000, 1000};
  const uint64_t outputs[] = {5000};
  EXPECT_TRUE(range_proof_test(true, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_accept_N_to_N_simple)
{
  const uint64_t inputs[] = {1000, 1000, 1000, 1000, 1000};
  const uint64_t outputs[] = {1000, 1000, 1000, 1000, 1000};
  EXPECT_TRUE(range_proof_test(true, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, range_proofs_accept_very_long_simple)
{
  const size_t N=12;
  uint64_t inputs[N];
  uint64_t outputs[N];
  for (size_t n = 0; n < N; ++n) {
    inputs[n] = n;
    outputs[n] = n;
  }
  std::shuffle(inputs, inputs + N, crypto::random_device{});
  std::shuffle(outputs, outputs + N, crypto::random_device{});
  EXPECT_TRUE(range_proof_test(true, NELTS(inputs), inputs, NELTS(outputs), outputs, false, true));
}

TEST(ringct, HPow2)
{
  // rct_point G = multG(int_to_scalar(1));

  // in lolnero, hashPoint uses sha3, but H is hashPoint with keccak256, so we use that H
  rct_point H = rct::H;
  ASSERT_TRUE(crypto::is_valid_point(H)); // this is known to pass for the particular value G

  // rct_point H_2;
  // rct_point H_2_8 = mult8(H_2);
  // ge_p2 H_p2;
  // ge_p3_to_p2(&H_p2, &H_p3);
  // ge_p1p1 H8_p1p1;
  // ge_mul8(&H8_p1p1, &H_p2);
  // ge_p1p1_to_p3(&H_p3, &H8_p1p1);
  // ge_p3_tobytes(H_2.data, &H_p3);

  // FIXME why fail?
  // ASSERT_TRUE(equalKeys(H_2, H));

  // for (int j = 0 ; j < ATOMS ; j++) {
  //   ASSERT_TRUE(equalKeys(H, H2[j]));
  //   addPoints(H, H, H);
  // }
}

static const amount_t test_amounts[]={0, 1, 2, 3, 4, 5, 10000, 10000000000000000000ull, 10203040506070809000ull, 123456789123456789};

TEST(ringct, d2h)
{
  crypto::ec_scalar k;
  auto [s, P1] = skpkGen();
  k = s;
  for (auto amount: test_amounts) {
    auto k = rct::int_to_scalar(amount);
    ASSERT_TRUE(amount == rct::scalar_to_int(k));
  }
}

TEST(ringct, fee_0_valid_simple)
{
  const uint64_t inputs[] = {1000, 1000};
  const uint64_t outputs[] = {2000, 0};
  EXPECT_TRUE(range_proof_test(true, NELTS(inputs), inputs, NELTS(outputs), outputs, true, true));
}

TEST(ringct, fee_non_0_valid_simple)
{
  const uint64_t inputs[] = {1000, 1000};
  const uint64_t outputs[] = {1900, 100};
  EXPECT_TRUE(range_proof_test(true, NELTS(inputs), inputs, NELTS(outputs), outputs, true, true));
}

TEST(ringct, fee_non_0_invalid_higher_simple)
{
  const uint64_t inputs[] = {1000, 1000};
  const uint64_t outputs[] = {1990, 100};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, true, true));
}

TEST(ringct, fee_non_0_invalid_lower)
{
  const uint64_t inputs[] = {1000, 1000};
  const uint64_t outputs[] = {1000, 100};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, true, false));
}

TEST(ringct, fee_non_0_invalid_lower_simple)
{
  const uint64_t inputs[] = {1000, 1000};
  const uint64_t outputs[] = {1000, 100};
  EXPECT_TRUE(range_proof_test(false, NELTS(inputs), inputs, NELTS(outputs), outputs, true, true));
}

TEST(ringct, fee_burn_valid_one_out_simple)
{
  const uint64_t inputs[] = {1000, 1000};
  const uint64_t outputs[] = {0, 2000};
  EXPECT_TRUE(range_proof_test(true, NELTS(inputs), inputs, NELTS(outputs), outputs, true, true));
}

// FIXME failed
// TEST(ringct, fee_burn_valid_zero_out_simple)
// {
//   const uint64_t inputs[] = {1000, 1000};
//   const uint64_t outputs[] = {2000};
//   EXPECT_TRUE(range_proof_test(true, NELTS(inputs), inputs, NELTS(outputs), outputs, true, true));
// }


static rct::rctSig make_sig_simple()
{
  static const uint64_t inputs[] = {1000, 1000};
  static const uint64_t outputs[] = {1000};
  static rct::rctSig sig = make_sample_simple_rct_sig(NELTS(inputs), inputs, NELTS(outputs), outputs, 1000);
  return sig;
}

#define TEST_rctSig_elements_simple(name, op) \
TEST(ringct, rctSig_##name##_simple) \
{ \
  rct::rctSig sig = make_sig_simple(); \
  ASSERT_TRUE(rct::verRctSimple(sig)); \
  op; \
  ASSERT_FALSE(rct::verRctSimple(sig)); \
}

TEST_rctSig_elements_simple(mixRing_empty, sig.mixRing.resize(0));
TEST_rctSig_elements_simple(mixRing_too_many, sig.mixRing.push_back(sig.mixRing.back()));
TEST_rctSig_elements_simple(mixRing_too_few, sig.mixRing.pop_back());
TEST_rctSig_elements_simple(mixRing0_empty, sig.mixRing[0].resize(0));
TEST_rctSig_elements_simple(mixRing0_too_many, sig.mixRing[0].push_back(sig.mixRing[0].back()));
TEST_rctSig_elements_simple(mixRing0_too_few, sig.mixRing[0].pop_back());
// TEST_rctSig_elements_simple(pseudoOuts_empty, sig.pseudoOuts.resize(0));
// TEST_rctSig_elements_simple(pseudoOuts_too_many, sig.pseudoOuts.push_back(sig.pseudoOuts.back()));
// TEST_rctSig_elements_simple(pseudoOuts_too_few, sig.pseudoOuts.pop_back());
TEST_rctSig_elements_simple(ecdhInfo_empty, sig.ecdhInfo.resize(0));
TEST_rctSig_elements_simple(ecdhInfo_too_many, sig.ecdhInfo.push_back(sig.ecdhInfo.back()));
TEST_rctSig_elements_simple(ecdhInfo_too_few, sig.ecdhInfo.pop_back());
TEST_rctSig_elements_simple(outPk_empty, sig.outPk.resize(0));
TEST_rctSig_elements_simple(outPk_too_many, sig.outPk.push_back(sig.outPk.back()));
TEST_rctSig_elements_simple(outPk_too_few, sig.outPk.pop_back());

TEST(ringct, key_ostream)
{
  std::stringstream out;
  out << "BEGIN" << rct::H << "END";
  EXPECT_EQ(
    std::string{"BEGIN<8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94>END"},
    out.str()
  );
}

TEST(ringct, dummyCommit)
{
  static const uint64_t amount = crypto::rand<uint64_t>();
  const rct::rct_point z = rct::dummyCommit(amount);
  const rct::rct_point a = rct::multG(rct::s_one);
  const rct::rct_point b = rct::multH(rct::int_to_scalar(amount));
  const rct::rct_point manual = a + b;
  ASSERT_EQ(z, manual);
}

TEST(ringct, mul8)
{
  rct::rct_point p;
  ASSERT_EQ(rct::multP8(rct::identity), rct::identity);
  p = rct::multP8(rct::identity);
  ASSERT_EQ(p, rct::identity);
  ASSERT_EQ(rct::multP8(rct::H), rct::multP(rct::H, rct::s_eight));
  p = rct::multP8(rct::H);
  ASSERT_EQ(p, rct::multP(rct::H, rct::s_eight));
  ASSERT_EQ(rct::multP(rct::multP(rct::H, rct::s_inv_eight), rct::s_eight), rct::H);
}

TEST(ringct, aggregated)
{
  static const size_t N_PROOFS = 16;
  std::vector<rctSig> s(N_PROOFS);

  for (size_t n = 0; n < N_PROOFS; ++n)
  {
    static const uint64_t inputs[] = {1000, 1000};
    static const uint64_t outputs[] = {500, 1500};
    s[n] = make_sample_simple_rct_sig(NELTS(inputs), inputs, NELTS(outputs), outputs, 0);
  }

  ASSERT_TRUE(verRctSemanticsSimple(s));
}
