#include "sha3.hpp"
#include <openssl/evp.h>

void handleErrors(void) {
  printf("sha3 error, wow is ded\n");
  exit(1);
}

void sha3(const void *data, size_t length, uint8_t *hash)
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
  if(1 != EVP_DigestFinal(mdctx, (unsigned char*)hash, NULL)) {
    handleErrors();
  }

  EVP_MD_CTX_free(mdctx);
}

void sha3_as_keccak1600(const uint8_t *in, size_t inlen, uint8_t *md) {
  sha3((const void*) in, inlen, md);
}

void sha3_as_keccak_256(const uint8_t *in, size_t inlen, uint8_t *md) {
  sha3((const void*) in, inlen, md);
}
