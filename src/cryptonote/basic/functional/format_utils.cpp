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


  //---------------------------------------------------------------
  std::optional<std::vector<tx_extra_field>> parse_tx_extra(const epee::blob::span tx_extra)
  {
    std::vector<tx_extra_field> tx_extra_fields;

    if(tx_extra.empty())
      return tx_extra_fields;

    std::string extra_str = epee::string_tools::blob_to_string(tx_extra);
    std::istringstream iss(extra_str);
    binary_archive<false> ar(iss);

    bool eof = false;
    while (!eof)
    {
      tx_extra_field field;
      bool r = ::do_serialize(ar, field);
      LOG_WITH_LEVEL_2_AND_RETURN_UNLESS
        (
         r
         , {}
         , "failed to deserialize extra field. extra = "
         << epee::string_tools::buff_to_hex_nodelimer(epee::string_tools::blob_to_string(tx_extra))
         );
      tx_extra_fields.push_back(field);

      std::ios_base::iostate state = iss.rdstate();
      eof = (EOF == iss.peek());
      iss.clear(state);
    }
    LOG_WITH_LEVEL_2_AND_RETURN_UNLESS
      (
       ::serialization::check_stream_state(ar)
       , {}
       , "failed to deserialize extra field. extra = "
       << epee::string_tools::buff_to_hex_nodelimer(epee::string_tools::blob_to_string(tx_extra))
       );

    return tx_extra_fields;
  }

  //---------------------------------------------------------------
  std::optional<crypto::public_key> get_tx_pub_key_from_extra(const std::vector<uint8_t>& tx_extra)
  {
    const auto maybe_tx_extra_fields = parse_tx_extra(tx_extra);

    if (!maybe_tx_extra_fields) return {};

    tx_extra_pub_key pub_key_field;
    if(!find_tx_extra_field_by_type(*maybe_tx_extra_fields, pub_key_field))
      return {};

    return pub_key_field.pub_key;
  }
  //---------------------------------------------------------------
  std::optional<crypto::public_key> get_tx_pub_key_from_extra(const transaction_prefix& tx_prefix)
  {
    return get_tx_pub_key_from_extra(tx_prefix.extra);
  }
  //---------------------------------------------------------------
  std::optional<crypto::public_key> get_tx_pub_key_from_extra(const transaction& tx)
  {
    return get_tx_pub_key_from_extra(tx.extra);
  }

  //---------------------------------------------------------------
  bool is_out_to_acc
  (
   const account_keys& acc
   , const txout_to_key& out_key
   , const std::optional<crypto::public_key>& tx_pub_key
   , const std::vector<crypto::public_key>& additional_tx_pub_keys
   , const size_t output_index
   )
  {
    if (tx_pub_key) {
      const std::optional<crypto::tx_ecdh_shared_secret> tx_shared_secret =
        crypto::derive_tx_ecdh_shared_secret(*tx_pub_key, acc.m_view_secret_key);

      LOG_ERROR_AND_RETURN_UNLESS(tx_shared_secret, false, "Failed to generate key derivation");

      const std::optional<crypto::public_key> pk =
        crypto::derive_tx_output_public_key_from_spend_public_key
        (*tx_shared_secret, output_index, acc.m_account_address.m_spend_public_key);

      LOG_ERROR_AND_RETURN_UNLESS(pk, false, "Failed to derive public key");
      if (*pk == out_key.key) {
        return true;
      }
    }

    // try additional tx pubkeys if available
    if (!additional_tx_pub_keys.empty())
    {
      LOG_ERROR_AND_RETURN_UNLESS
        (output_index < additional_tx_pub_keys.size(), false, "wrong number of additional tx pubkeys");

      const auto tx_shared_secret_2 =
        crypto::derive_tx_ecdh_shared_secret(additional_tx_pub_keys[output_index], acc.m_view_secret_key);
      LOG_ERROR_AND_RETURN_UNLESS(tx_shared_secret_2, false, "Failed to generate key derivation");

      const auto tx_out_pk = crypto::derive_tx_output_public_key_from_spend_public_key
        (*tx_shared_secret_2, output_index, acc.m_account_address.m_spend_public_key);

      LOG_ERROR_AND_RETURN_UNLESS(tx_out_pk, false, "Failed to derive public key");

      return *tx_out_pk == out_key.key;
    }
    return false;
  }

  //---------------------------------------------------------------
  std::optional<subaddress_receive_info> is_out_to_acc_precomp
  (
   const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses
   , const crypto::public_key& tx_out_key
   , const std::optional<crypto::tx_ecdh_shared_secret>& tx_shared_secret
   , const std::vector<crypto::tx_ecdh_shared_secret>& tx_shared_secrets
   , const size_t output_index
   )
  {
    // try the shared tx pubkey
    if (tx_shared_secret) {
      const std::optional<crypto::public_key> spend_pk =
        crypto::derive_spend_public_key_from_tx_output_public_key(*tx_shared_secret, output_index, tx_out_key);

      auto found = subaddresses.find(spend_pk.value_or(crypto::null_pkey));

      if (found != subaddresses.end())
        return subaddress_receive_info{ found->second, *tx_shared_secret};
    }

    // try additional tx pubkeys if available
    if (!tx_shared_secrets.empty())
    {
      LOG_ERROR_AND_RETURN_UNLESS(output_index < tx_shared_secrets.size(), std::nullopt, "wrong number of additional derivations");
      const auto spend_pk_1 = crypto::derive_spend_public_key_from_tx_output_public_key
        (tx_shared_secrets[output_index], output_index, tx_out_key);

      const auto found_1 = subaddresses.find(spend_pk_1.value_or(crypto::null_pkey));

      if (found_1 != subaddresses.end())
        return subaddress_receive_info{ found_1->second, tx_shared_secrets[output_index] };
    }
    return {};
  }

  //---------------------------------------------------------------
  crypto::hash get_blob_hash(const blobdata_ref& blob)
  {
    return crypto::sha3(epee::string_tools::string_view_to_blob_view(blob));
  }
  //---------------------------------------------------------------
  crypto::hash get_blob_hash(const blobdata& blob)
  {
    return crypto::sha3(epee::string_tools::string_to_blob(blob));
  }

  //---------------------------------------------------------------
  std::string short_hash_str(const crypto::hash& h)
  {
    std::string res = epee::string_tools::pod_to_hex(h);
    LOG_ERROR_AND_RETURN_UNLESS(res.size() == 64, res, "wrong hash256 with epee::string_tools::pod_to_hex conversion");
    auto erased_pos = res.erase(8, 48);
    res.insert(8, "....");
    return res;
  }
}
