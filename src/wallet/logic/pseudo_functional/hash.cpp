// Copyright (c) 2021, The Lolnero Project
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


#include "hash.hpp"

#include <openssl/evp.h>

namespace wallet {
namespace logic {
namespace pseudo_functional {
namespace hash {

  //----------------------------------------------------------------------------------------------------
  void hash_m_transfer(const tools::wallet2::transfer_details & transfer, crypto::hash &hash)
  {
    EVP_MD_CTX *state= EVP_MD_CTX_new();
    EVP_DigestInit_ex(state, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(state, (const uint8_t *) transfer.m_txid.data, sizeof(transfer.m_txid.data));
    EVP_DigestUpdate(state, (const uint8_t *) transfer.m_internal_output_index, sizeof(transfer.m_internal_output_index));
    EVP_DigestUpdate(state, (const uint8_t *) transfer.m_global_output_index, sizeof(transfer.m_global_output_index));
    EVP_DigestUpdate(state, (const uint8_t *) transfer.m_amount, sizeof(transfer.m_amount));
    EVP_DigestFinal(state, (uint8_t *) hash.data, NULL);
    EVP_MD_CTX_free(state);
  }

} // hash
} // pseudo_functional
} // logic
} // wallet
