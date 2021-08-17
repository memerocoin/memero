#include "hash.hpp"

namespace crypto {

hash sha3(const epee::blob::span x) {
  hash h;
  sha3_raw(x.data(), x.size(), h.data.data());
  return h;
}

void tree_hash(const hash *hashes, const std::size_t count, hash &root_hash) {
  ::tree_hash(reinterpret_cast<const uint8_t (*)[HASH_SIZE]>(hashes), count, reinterpret_cast<uint8_t *>(&root_hash));
}

}


CRYPTO_MAKE_HASHABLE_CPP(hash)
CRYPTO_MAKE_COMPARABLE_CPP(hash8)
