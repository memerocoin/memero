// this runs on the device

typedef uchar uint8_t;
typedef ulong uint64_t;

// state context
typedef struct {
  union {           // state:
    uint8_t b[200]; // 8-bit bytes
    uint64_t q[25]; // 64-bit words
  } st;
  int pt, rsiz, mdlen; // these don't overflow
} sha3_ctx_t;

#define KECCAKF_ROUNDS 24
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

void sha3_keccakf(uint64_t st[25]);
int sha3_init(sha3_ctx_t *c, int mdlen);
int sha3_update(sha3_ctx_t *c, __constant void *data, size_t len);
int sha3_update_private(sha3_ctx_t *c, __private void *data, size_t len);
int sha3_final(void *md, sha3_ctx_t *c);

// update the state with given number of rounds

void sha3_keccakf(uint64_t st[25]) {
  // constants
  const uint64_t keccakf_rndc[24] = {
      0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
      0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
      0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
      0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
      0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
      0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
      0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
      0x8000000000008080, 0x0000000080000001, 0x8000000080008008};
  const int keccakf_rotc[24] = {1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                                27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};
  const int keccakf_piln[24] = {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                                15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};

  // variables
  int i, j, r;
  uint64_t t, bc[5];

  // actual iteration
  for (r = 0; r < KECCAKF_ROUNDS; r++) {

    // Theta
    for (i = 0; i < 5; i++)
      bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

    for (i = 0; i < 5; i++) {
      t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
      for (j = 0; j < 25; j += 5)
        st[j + i] ^= t;
    }

    // Rho Pi
    t = st[1];
    for (i = 0; i < 24; i++) {
      j = keccakf_piln[i];
      bc[0] = st[j];
      st[j] = ROTL64(t, keccakf_rotc[i]);
      t = bc[0];
    }

    //  Chi
    for (j = 0; j < 25; j += 5) {
      for (i = 0; i < 5; i++)
        bc[i] = st[j + i];
      for (i = 0; i < 5; i++)
        st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
    }

    //  Iota
    st[0] ^= keccakf_rndc[r];
  }
}

// Initialize the context for SHA3

int sha3_init(sha3_ctx_t *c, int mdlen) {
  int i;

  for (i = 0; i < 25; i++)
    c->st.q[i] = 0;
  c->mdlen = mdlen;
  c->rsiz = 200 - 2 * mdlen;
  c->pt = 0;

  return 1;
}

// update state with more data

int sha3_update(sha3_ctx_t *c, __constant void *data, size_t len) {
  size_t i;
  int j;

  j = c->pt;
  for (i = 0; i < len; i++) {
    c->st.b[j++] ^= ((__constant uint8_t *)data)[i];
    if (j >= c->rsiz) {
      sha3_keccakf(c->st.q);
      j = 0;
    }
  }
  c->pt = j;

  return 1;
}

int sha3_update_private(sha3_ctx_t *c, __private void *data, size_t len) {
  size_t i;
  int j;

  j = c->pt;
  for (i = 0; i < len; i++) {
    c->st.b[j++] ^= ((__private uint8_t *)data)[i];
    if (j >= c->rsiz) {
      sha3_keccakf(c->st.q);
      j = 0;
    }
  }
  c->pt = j;

  return 1;
}

// finalize and output a hash

int sha3_final(void *md, sha3_ctx_t *c) {
  int i;

  c->st.b[c->pt] ^= 0x06;
  c->st.b[c->rsiz - 1] ^= 0x80;
  sha3_keccakf(c->st.q);

  for (i = 0; i < c->mdlen; i++) {
    ((uint8_t *)md)[i] = c->st.b[i];
  }

  return 1;
}


// lolnero
// License: MIT or BSD-3

#define templateHeaderSize 39
#define templateTailMaxSize 36
#define hashSize 32

typedef struct
{
  uint64_t nonce;
  uint8_t hashBound[hashSize];
  uint8_t header[templateHeaderSize];
  uint8_t tail[templateTailMaxSize];
  size_t tailSize;
  size_t loopSize;
} cl_mining_template;

typedef struct
{
  uint8_t hash[hashSize];
  uint64_t nonce;
  uint8_t valid;
} cl_mining_result_array;



void toGlobal(const uint8_t* x, global uint8_t* y, const size_t l) {
  for (size_t i = 0; i < l; i++) {
    y[i] = x[i];
  }
}

bool is_hash_bounded(const uint8_t* hash, constant uint8_t* hashBound) {
  for (size_t i = hashSize - 1; i >= 0; i--) {
    if (hash[i] > hashBound[i]) {
      return false;
    }
    else if (hash[i] < hashBound[i]) {
      return true;
    }
  }
  return true;
}

kernel void sha3
(
 constant cl_mining_template* mining_template
 , global cl_mining_result_array* mining_result_array
 )
{
  const size_t i = get_global_id(0);
  const size_t loop_size = mining_template->loopSize;

  uint64_t local_nonce = mining_template->nonce + (uint64_t)(i * loop_size);

  uint8_t hash[hashSize];
  bool valid = false;

  sha3_ctx_t sha3_header;
  sha3_init(&sha3_header, hashSize);
  sha3_update(&sha3_header, mining_template->header, templateHeaderSize);

  sha3_ctx_t sha3;

  for (size_t j = 0; j < loop_size; j++, local_nonce++) {
    sha3 = sha3_header;

    sha3_update_private(&sha3, &local_nonce, sizeof(uint64_t));
    sha3_update(&sha3, mining_template->tail, mining_template->tailSize);
    sha3_final(hash, &sha3);

    valid = is_hash_bounded(hash, mining_template->hashBound);

    if (valid) break;
  }

  if (!valid) local_nonce--;

  toGlobal(hash, mining_result_array[i].hash, hashSize);

  mining_result_array[i].nonce = local_nonce;
  mining_result_array[i].valid = valid;
};
