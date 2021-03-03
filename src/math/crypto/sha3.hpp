// sha3.h
// Copyright (c) 2020, The lolnero Project
//
// License: BSD3

#pragma once

#include <stddef.h>
#include <inttypes.h>

void sha3(const void *data, size_t length, char *hash);
void sha3_as_keccak1600(const uint8_t *in, size_t inlen, uint8_t *md);
void sha3_as_keccak_256(const uint8_t *in, size_t inlen, uint8_t *md);
