#pragma once

#include "math/crypto/functional/hash-ops.hpp"
#include "math/crypto/functional/hash.hpp"

#include <cstdint>

namespace crypto
{

void tree_hash(const uint8_t (*hashes)[HASH_SIZE], size_t count, uint8_t *root_hash) noexcept;

}

