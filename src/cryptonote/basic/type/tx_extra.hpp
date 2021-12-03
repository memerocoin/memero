// Copyright (c) 2014-2020, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include "math/group/functional/group.hpp"

#include "tools/serialization/serialization.h"
#include "tools/serialization/binary_archive.h"
#include "tools/serialization/crypto.h"
#include "tools/serialization/variant.h"
#include "tools/serialization/containers.h"

#include <boost/variant.hpp>

#define TX_EXTRA_TAG_TX_PUBKEY 0x01
#define TX_EXTRA_TAG_TX_OUTPUT_PUBKEYS     0x04

namespace cryptonote
{
  struct tx_extra_tx_public_key
  {
    crypto::ec_point_unsafe pub_key_unsafe;

    BEGIN_SERIALIZE()
      FIELD(pub_key_unsafe)
    END_SERIALIZE()
  };

  // per-output additional tx pubkey for multi-destination transfers involving at least one subaddress
  struct tx_extra_output_ecdh_public_keys
  {
    std::vector<crypto::ec_point_unsafe> pub_keys_unsafe;

    BEGIN_SERIALIZE()
      FIELD(pub_keys_unsafe)
    END_SERIALIZE()
  };

  // tx_extra_field format, except tx_extra_padding and tx_extra_tx_public_key:
  //   varint tag;
  //   varint size;
  //   varint data[];
  typedef boost::variant
  <
      tx_extra_tx_public_key
    , tx_extra_output_ecdh_public_keys
    > tx_extra_field;
}

VARIANT_TAG(binary_archive, cryptonote::tx_extra_tx_public_key, TX_EXTRA_TAG_TX_PUBKEY);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_output_ecdh_public_keys, TX_EXTRA_TAG_TX_OUTPUT_PUBKEYS);
