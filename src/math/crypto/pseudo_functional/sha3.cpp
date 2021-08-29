#include "sha3.hpp"

#include <openssl/evp.h>

#include <exception>

void handleErrors() noexcept {
  printf("sha3 error, lol is ded\n");
  std::terminate();
}

void sha3_raw(const uint8_t *data, const size_t length, uint8_t *hash) noexcept
{
  EVP_MD_CTX *mdctx;

  if((mdctx = EVP_MD_CTX_new()) == NULL) {
    handleErrors();
  }

  if(1 != EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL)) {
    handleErrors();
  }

  if(1 != EVP_DigestUpdate(mdctx, data, length)) {
    handleErrors();
  }

  /* the digest context ctx is automatically cleaned up. */
  if(1 != EVP_DigestFinal(mdctx, hash, NULL)) {
    handleErrors();
  }

  EVP_MD_CTX_free(mdctx);
}
