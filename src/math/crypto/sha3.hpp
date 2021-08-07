// sha3.h
// Copyright (c) 2020, The lolnero Project
//
// License: BSD3

#pragma once

#include <cstdint>
#include <cstddef>

void sha3_raw(const uint8_t *data, const size_t length, uint8_t *hash);
