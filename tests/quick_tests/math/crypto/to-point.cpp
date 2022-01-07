/*

  Copyright 2021 fuwa

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

#include <gtest/gtest.h>

#include "math/group/functional/group.hpp"
#include "math/group/functional/curve25519_cryptonote_extension.hpp"
#include "math/crypto/controller/keyGen.hpp"

using namespace crypto;

TEST(H2P, works_on_G)
{
  const auto hashG =
    from_hex("14f116f01128c766e5fe380e7bbaafe9f843c56ff03442341fe3202113d1535e");

  EXPECT_TRUE(hashG);

  EXPECT_EQ(viaFieldMult8(generator), *hashG);
}
