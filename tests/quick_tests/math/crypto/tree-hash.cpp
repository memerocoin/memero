/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include <gtest/gtest.h>

#include "tree-hash-raw.hpp"

#include "math/crypto/functional/tree-hash.hpp"
#include "math/crypto/controller/keyGen.hpp"

#include <algorithm>

using namespace crypto;

hash hashGen() {
  const auto x = randomScalar();
  return d2h(x);
}

std::optional<hash> tree_hash_raw(const std::span<const hash> hashes) noexcept {
  hash root_hash;
  tree_hash(reinterpret_cast<const uint8_t (*)[HASH_SIZE]>(hashes.data()), hashes.size(), root_hash.data.data());
  return root_hash;
}

TEST(quick_tree_hash, random_1_to_1000) {
  for (size_t i = 1; i <= 1000; i++) {
    std::vector<hash> xs;

    std::generate_n
      (
       std::back_inserter(xs)
       , i
       , hashGen
       );

    EXPECT_EQ(tree_hash(xs), tree_hash_raw(xs));
  }
}

TEST(quick_tree_hash, random_10000) {
  std::vector<hash> xs;

  std::generate_n
    (
     std::back_inserter(xs)
       , 10000
       , hashGen
     );

  EXPECT_EQ(tree_hash(xs), tree_hash_raw(xs));
}


// TEST(tree_hash, random_1_m) {
//   std::vector<hash> xs;

//   std::generate_n
//     (
//      std::back_inserter(xs)
//      , 1000000
//      , hashGen
//      );

//   EXPECT_EQ(tree_hash(xs), tree_hash_raw(xs));
// }

