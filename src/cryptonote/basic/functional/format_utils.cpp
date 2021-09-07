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

#include "format_utils.hpp"

#include "tools/epee/include/string_tools.h"
#include "tools/serialization/string.h" // don't remove, or face core dump

#include "math/ringct/pseudo_functional/rctSigs.hpp"

#include "wallet/device/functional/device_default.hpp"

#include <boost/algorithm/string.hpp>


using namespace epee;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "cn"

namespace cryptonote
{
  //---------------------------------------------------------------
  crypto::hash get_transaction_prefix_hash(const transaction_prefix& tx)
  {
    std::ostringstream s;
    binary_archive<true> a(s);
    ::serialization::serialize(a, const_cast<transaction_prefix&>(tx));

    return crypto::sha3(epee::string_tools::string_to_blob(s.str()));
  }

  //---------------------------------------------------------------
  std::optional<std::pair<keypair, crypto::key_image>> derive_key_image_helper
  (
   const account_keys& ack
   , const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses
   , const crypto::public_key& out_key
   , const std::optional<crypto::public_key>& tx_public_key
   , const std::vector<crypto::public_key>& additional_tx_public_keys
   , const size_t real_output_index
   )
  {
    const std::optional<crypto::tx_ecdh_shared_secret> recv_tx_shared_secret =
      tx_public_key
      ? crypto::derive_tx_ecdh_shared_secret(*tx_public_key, ack.m_view_secret_key)
      : std::optional<crypto::tx_ecdh_shared_secret>();

    // if (!recv_tx_shared_secret)
    // {
    //   LOG_WARNING("key image helper: failed to derive_tx_ecdh_shared_secret(" << tx_public_key << ", " << ack.m_view_secret_key << ")");
    //   return false;
    // }

    std::vector<crypto::tx_ecdh_shared_secret> additional_recv_tx_shared_secrets;
    for (size_t i = 0; i < additional_tx_public_keys.size(); ++i)
    {
      const std::optional<crypto::tx_ecdh_shared_secret> additional_recv_tx_shared_secret =
        crypto::derive_tx_ecdh_shared_secret(additional_tx_public_keys[i], ack.m_view_secret_key);
      if (!additional_recv_tx_shared_secret)
      {
        LOG_WARNING("key image helper: failed to derive_tx_ecdh_shared_secret(" << additional_tx_public_keys[i] << ", " << ack.m_view_secret_key << ")");
      }
      else
      {
        additional_recv_tx_shared_secrets.push_back(*additional_recv_tx_shared_secret);
      }
    }

    std::optional<subaddress_receive_info> subaddr_recv_info =
      is_out_to_acc_precomp
      (
       subaddresses, out_key, recv_tx_shared_secret, additional_recv_tx_shared_secrets, real_output_index
       );

    LOG_ERROR_AND_RETURN_UNLESS
      (
       subaddr_recv_info
       , {}
       , "key image helper: given output pubkey doesn't seem to belong to this address"
       );

    return derive_key_image_helper_precomp
      (
       ack
       , out_key
       , subaddr_recv_info->tx_shared_secret
       , real_output_index
       , subaddr_recv_info->index
       );
  }

  //---------------------------------------------------------------
  std::optional<std::pair<keypair, crypto::key_image>> derive_key_image_helper_precomp
  (
   const account_keys& ack
   , const crypto::public_key& out_key
   , const crypto::tx_ecdh_shared_secret& recv_tx_shared_secret
   , const size_t real_output_index
   , const subaddress_index& received_index
   )
  {
    keypair in_ephemeral;
    crypto::key_image ki;

    if (ack.m_spend_secret_key == crypto::null_skey)
    {
      // for watch-only wallet, simply copy the known output pubkey
      in_ephemeral.pub = out_key;
      in_ephemeral.sec = crypto::null_skey;
    }
    else
    {
      // derive secret key with subaddress - step 1: original CN derivation
      const auto spend_sk = ack.m_spend_secret_key;
      if (is_not_reduced(spend_sk)) return {};

        // computes Hs(a*R || idx) + b
      const crypto::secret_key derived_tx_output_secret_key =
        derive_tx_output_secret_key_from_spend_secret_key(recv_tx_shared_secret, real_output_index, spend_sk);

      // add subaddress secret key: Hs(a || index_major || index_minor)
      const crypto::secret_key key_offset =
        received_index.is_zero()
        ? crypto::s2sk(crypto::s_0)
        : device::get_subaddress_secret_key(ack.m_view_secret_key, received_index)
        ;

      in_ephemeral.sec = crypto::s2sk(derived_tx_output_secret_key + key_offset);
      in_ephemeral.pub = to_pk(in_ephemeral.sec);

      LOG_ERROR_AND_RETURN_UNLESS(in_ephemeral.pub == out_key,
           {}, "key image helper precomp: given output pubkey doesn't match the derived one");
    }

    ki = crypto::derive_key_image(in_ephemeral.sec);
    return {{in_ephemeral, ki}};
  }

}
