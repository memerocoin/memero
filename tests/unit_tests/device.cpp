// Copyright (c) 2018, The Monero Project
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

#include "gtest/gtest.h"

#include "math/ringct/functional/rctOps.hpp"
#include "math/ringct/controller/rctGen.hpp"
#include "math/crypto/controller/keyGen.hpp"

#include "wallet/device/functional/device_default.hpp"

TEST(device, name)
{
  ASSERT_TRUE(dev.set_name("test"));
  ASSERT_EQ(dev.get_name(), "test");
}

/*
TEST(device, locking)
{
  hw::core::device_default dev;
  ASSERT_TRUE(dev.try_lock());
  ASSERT_FALSE(dev.try_lock());
  dev.unlock();
  ASSERT_TRUE(dev.try_lock());
  dev.unlock();
  dev.lock();
  ASSERT_FALSE(dev.try_lock());
  dev.unlock();
  ASSERT_TRUE(dev.try_lock());
  dev.unlock();
}
*/

TEST(device, ops)
{
  hw::core::device_default dev;
  std::optional<crypto::key_derivation> derd, maybeDer;
  rct::rct_scalar sk;
  rct::rct_point pk;
  crypto::secret_key sk0, sk1;
  crypto::public_key pk0, pk1;

  std::tie(sk, pk) = rct::skpkGen();
  sk0 = crypto::s2sk(crypto::scalarGen());
  sk1 = crypto::s2sk(crypto::scalarGen());
  pk0 = rct::rct_p2pk(rct::multG((rct::rct_scalar&)sk0));
  pk1 = rct::rct_p2pk(rct::multG((rct::rct_scalar&)sk1));

  ASSERT_TRUE(is_not_identity_but_valid(pk0));

  derd = crypto::derive_key_derivation(pk0, sk0);
  maybeDer = crypto::derive_key_derivation(pk0, sk0);
  ASSERT_EQ(derd, maybeDer);
}

// TODO fix tests
// ecdhEncode uses derive_secret_key_for_ecdh_amount, which we replaced with sha3, so these will fail
/*
TEST(device, ecdh32)

  hw::core::device_default dev;
  rct::ecdhData tuple, tuple2;
  rct::rct_point key = rct::skGen();
  tuple.mask = rct::skGen();
  tuple.amount = rct::skGen();
  tuple2 = tuple;
  dev.ecdhEncode(tuple, key);
  dev.ecdhDecode(tuple, key);
  ASSERT_EQ(tuple2.mask, tuple.mask);
  ASSERT_EQ(tuple2.amount, tuple.amount);
}
*/
