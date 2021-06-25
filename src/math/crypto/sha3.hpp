// sha3.h
// Copyright (c) 2020, The lolnero Project
//
// License: BSD3

#pragma once

#include <cstdint>
#include <cstddef>

void sha3(const uint8_t *data, const size_t length, uint8_t *hash);
void sha3_as_keccak1600(const uint8_t *in, const size_t inlen, uint8_t *md);
void sha3_as_keccak_256(const uint8_t *in, const size_t inlen, uint8_t *md);
