#include "hash.hpp"

namespace crypto {

hash sha3(const epee::blob::span x) {
  hash h;
  sha3_raw(x.data(), x.size(), h.data.data());
  return h;
}

hash tree_hash(const std::span<const hash> hashes) {
  hash root_hash;
  ::tree_hash(reinterpret_cast<const uint8_t (*)[HASH_SIZE]>(hashes.data()), hashes.size(), reinterpret_cast<uint8_t *>(&root_hash));
  return root_hash;
}

}


