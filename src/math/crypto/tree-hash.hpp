#pragma once

#include "hash-ops.hpp"

void tree_hash(const char (*hashes)[HASH_SIZE], size_t count, char *root_hash);
