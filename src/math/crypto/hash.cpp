#include "hash.hpp"

namespace crypto {

void cn_fast_hash(const void *data, size_t length, uint8_t *hash) {
  ::sha3(data, length, hash);
}

void cn_fast_hash(const void *data, std::size_t length, hash &hash) {
  ::sha3(data, length, reinterpret_cast<uint8_t *>(&hash));
}

hash cn_fast_hash(const void *data, std::size_t length) {
  hash h;
  ::sha3(data, length, reinterpret_cast<uint8_t *>(&h));
  return h;
}

void sha3(const void *data, std::size_t length, hash &hash) {
  ::sha3(data, length, reinterpret_cast<uint8_t *>(&hash));
}

void cn_slow_hash_prehashed(const void *data, std::size_t length, hash &hash, int variant = 0, uint64_t height = 0) {
  cn_fast_hash(data, length, reinterpret_cast<uint8_t *>(&hash));
}

void tree_hash(const hash *hashes, std::size_t count, hash &root_hash) {
  ::tree_hash(reinterpret_cast<const uint8_t (*)[HASH_SIZE]>(hashes), count, reinterpret_cast<uint8_t *>(&root_hash));
}

}


CRYPTO_MAKE_HASHABLE_CPP(hash)
CRYPTO_MAKE_COMPARABLE_CPP(hash8)
