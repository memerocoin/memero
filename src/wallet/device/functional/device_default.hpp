// Copyright (c) 2017-2020, The Monero Project
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

#pragma once

#include "cryptonote/basic/cryptonote_basic.h"
#include "cryptonote/basic/account.h"
#include "cryptonote/basic/subaddress_index.h"
#include "cryptonote/tx/cryptonote_tx_utils.h"

namespace device {
  /* ======================================================================= */
  /*                             WALLET & ADDRESS                            */
  /* ======================================================================= */

  crypto::chacha_key generate_chacha_key(const cryptonote::account_keys &keys, const uint64_t kdf_rounds);

  /* ======================================================================= */
  /*                               SUB ADDRESS                               */
  /* ======================================================================= */

  crypto::public_key get_subaddress_spend_public_key
  (
   const cryptonote::account_keys& keys
   , const cryptonote::subaddress_index& index
   );

  std::vector<crypto::public_key> get_subaddress_spend_public_keys
  (
   const cryptonote::account_keys &keys
   , const uint32_t account
   , const uint32_t begin
   , const uint32_t end
   );

  cryptonote::account_public_address get_subaddress
  (
   const cryptonote::account_keys& keys
   , const cryptonote::subaddress_index &index
   );

  crypto::secret_key get_subaddress_secret_key
  (
   const crypto::secret_key &sec
   , const cryptonote::subaddress_index &index
   );

  /* ======================================================================= */
  /*                            DERIVATION & KEY                             */
  /* ======================================================================= */

  bool verify_keys(const crypto::secret_key &secret_key, const crypto::public_key &public_key);
}
