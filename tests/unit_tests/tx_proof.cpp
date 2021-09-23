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

#include "tools/epee/include/string_tools.h"

#include "math/crypto/functional/key.hpp"
#include "math/crypto/functional/hash.hpp"
#include "math/crypto/controller/keyGen.hpp"

#include <boost/algorithm/string.hpp>

TEST(tx_proof, prove_verify_v2)
{
    crypto::secret_key r = s2sk(crypto::scalarGen());

    // A = aG
    // B = bG
    crypto::secret_key a,b;
    crypto::public_key A,B;
    std::tie(a, A) = crypto::generate_keys({});
    std::tie(b, B) = crypto::generate_keys({});

    // R_B = rB
    crypto::public_key R_B = crypto::p2pk(B ^ r);

    // R_G = rG
    crypto::public_key R_G = crypto::p2pk(crypto::multBase(r));

    crypto::schnorr_signature sig;

    // Message data
    crypto::hash prefix_hash;
    constexpr std::string_view data = "hash input";
    prefix_hash = crypto::sha3(epee::string_tools::string_view_to_blob_view(data));

    // Generate/verify valid v2 proof with standard address
    sig = crypto::generate_tx_proof(prefix_hash, std::nullopt, r);
    ASSERT_TRUE(crypto::verify_tx_proof(prefix_hash, R_G, std::nullopt, sig));

    // Generate/verify valid v2 proof with subaddress
    sig = crypto::generate_tx_proof(prefix_hash, B, r);
    ASSERT_TRUE(crypto::verify_tx_proof(prefix_hash, R_B, B, sig));

    // Randomly-distributed test points
    crypto::secret_key evil_a, evil_b, evil_d, evil_r;
    crypto::public_key evil_A, evil_B, evil_D, evil_R;
    std::tie(evil_a, evil_A) = crypto::generate_keys({});
    std::tie(evil_b, evil_B) = crypto::generate_keys({});
    std::tie(evil_d, evil_D) = crypto::generate_keys({});
    std::tie(evil_r, evil_R) = crypto::generate_keys({});

    // Selectively choose bad point in v2 proof (bad)
    sig = crypto::generate_tx_proof(prefix_hash, B, r);
    ASSERT_FALSE(crypto::verify_tx_proof(prefix_hash, evil_R, B, sig));
    ASSERT_FALSE(crypto::verify_tx_proof(prefix_hash, R_B, evil_B, sig));
}
