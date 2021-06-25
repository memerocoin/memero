#pragma once

#include "hash-ops.hpp"

#include <cstdint>

void tree_hash(const uint8_t (*hashes)[HASH_SIZE], size_t count, uint8_t *root_hash);
