#include "sha3.hpp"

extern "C"
{
#include "sha3.h"
}

void sha3_raw(const uint8_t *data, const size_t length, uint8_t *hash) noexcept
{
  sha3_HashBuffer(256, SHA3_FLAGS_NONE, data, length, hash, 32);
}
