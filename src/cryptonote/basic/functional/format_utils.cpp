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
  crypto::hash get_blob_hash(const blobdata_ref blob)
  {
    return crypto::sha3(epee::string_tools::string_view_to_blob_view(blob));
  }
  //---------------------------------------------------------------
  crypto::hash get_blob_hash(const blobdata blob)
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

  //---------------------------------------------------------------
  crypto::hash calculate_transaction_prunable_hash
  (
   const transaction& t
   , const cryptonote::blobdata_ref blob
   )
  {

    LOG_ERROR_AND_THROW_IF
      (
       t.version == 1
       , "error trying to calculate prunable_hash on v1 tx"
       );

    const unsigned int unprunable_size = t.unprunable_size;

    LOG_ERROR_AND_THROW_UNLESS
      (
       unprunable_size <= blob.size()
       , "Inconsistent transaction unprunable and blob sizes"
       );

    return cryptonote::get_blob_hash
      (blobdata_ref(blob.data() + unprunable_size, blob.size() - unprunable_size)
       );
  }

  //---------------------------------------------------------------
  crypto::hash calculate_transaction_hash(const transaction& t)
  {
    // v1 transactions hash the entire blob
    if (t.version == 1)
    {
      return get_object_hash(t);
    }

    // v2 transactions hash different parts together, than hash the set of those hashes
    crypto::hash hashes[3];

    // prefix
    hashes[0] = get_transaction_prefix_hash(t);

    const blobdata blob = tx_to_blob(t);
    const unsigned int unprunable_size = t.unprunable_size;
    const unsigned int prefix_size = t.prefix_size;

    // base rct
    if (! (prefix_size <= unprunable_size && unprunable_size <= blob.size() )) {
      LOG_FATAL("Inconsistent transaction prefix, unprunable and blob sizes");
    }

    hashes[1] = cryptonote::get_blob_hash(blobdata_ref(blob.data() + prefix_size, unprunable_size - prefix_size));

    // prunable rct
    if (t.ringct_essential.type == rct::RCTTypeNull)
    {
      hashes[2] = crypto::null_hash;
    }
    else
    {
      cryptonote::blobdata_ref blobref(blob);
      hashes [2] = calculate_transaction_prunable_hash(t, blobref);
    }

    // the tx hash is the hash of the 3 hashes
    return crypto::sha3(epee::blob::span((const uint8_t*)hashes, sizeof(hashes)));
  }

  //---------------------------------------------------------------
  crypto::secret_key encrypt_key(const crypto::secret_key key, const epee::wipeable_string &passphrase)
  {
    const crypto::ec_scalar offset =
      crypto::hash_to_scalar(epee::string_tools::string_to_blob(passphrase));
    return crypto::s2sk(key + offset);
  }
  //---------------------------------------------------------------
  crypto::secret_key decrypt_key(const crypto::secret_key key, const epee::wipeable_string &passphrase)
  {
    const crypto::ec_scalar offset =
      crypto::hash_to_scalar(epee::string_tools::string_to_blob(passphrase));
    return crypto::s2sk(key - offset);
  }

  //---------------------------------------------------------------
  crypto::hash get_tx_tree_hash(const std::vector<crypto::hash>& tx_hashes)
  {
    return tree_hash(tx_hashes);
  }
  //---------------------------------------------------------------
  crypto::hash get_tx_tree_hash(const block& b)
  {
    const crypto::hash h = fill_transaction_hash(b.miner_tx);

    std::vector<crypto::hash> txs = {h};

    std::copy
      (
       b.tx_hashes.begin()
       , b.tx_hashes.end()
       , std::back_inserter(txs)
       );

    return get_tx_tree_hash(txs);
  }

  //---------------------------------------------------------------
  uint64_t get_transaction_weight(const transaction &tx, const size_t blob_size)
  {
    return blob_size;
  }
  //---------------------------------------------------------------
  uint64_t get_transaction_weight(const transaction &tx)
  {
    size_t blob_size;
    if (tx.is_blob_size_valid())
      {
        blob_size = tx.blob_size;
      }
    else
      {
        std::ostringstream s;
        binary_archive<true> a(s);
        ::serialization::serialize(a, const_cast<transaction&>(tx));
        blob_size = s.str().size();
      }
    return get_transaction_weight(tx, blob_size);
  }

  //---------------------------------------------------------------
  uint64_t get_tx_fee(const transaction& tx)
  {
    if (tx.version > 1)
      {
        return tx.ringct_essential.fee;
      }
    else return 0;
  }

  //---------------------------------------------------------------
  std::vector<crypto::public_key> get_tx_pub_keys_from_extra(const transaction& tx)
  {
    const auto x = get_tx_pub_key_from_extra(tx);
    std::vector<crypto::public_key> xs = get_additional_tx_pub_keys_from_extra(tx);

    if(x) {
      xs.insert(xs.begin(), *x);
    }

    return xs;
  }

  //---------------------------------------------------------------
  uint64_t get_block_height(const block& b)
  {
    LOG_ERROR_AND_RETURN_UNLESS(b.miner_tx.vin.size() == 1, 0, "wrong miner tx in block: " << get_block_hash(b) << ", b.miner_tx.vin.size() != 1");
    CHECKED_GET_SPECIFIC_VARIANT(b.miner_tx.vin[0], const txin_gen, coinbase_in, 0);
    return coinbase_in.height;
  }

  //---------------------------------------------------------------
  bool check_inputs_types_supported(const transaction& tx)
  {
    for(const auto& in: tx.vin)
    {
      LOG_ERROR_AND_RETURN_UNLESS
        (
         in.type() == typeid(txin_to_key)
         , false
         , "wrong variant type: "
         << in.type().name() << ", expected " << typeid(txin_to_key).name()
         << ", in transaction id=" << fill_transaction_hash(tx)
         );

    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool check_outs_valid(const transaction& tx)
  {
    for(const tx_out& out: tx.vout)
    {
      LOG_ERROR_AND_RETURN_UNLESS(out.target.type() == typeid(txout_to_key), false, "wrong variant type: "
        << out.target.type().name() << ", expected " << typeid(txout_to_key).name()
        << ", in transaction id=" << fill_transaction_hash(tx));

      if (tx.version == 1)
      {
        LOG_WITH_LEVEL_0_AND_RETURN_UNLESS(0 < out.amount, false, "zero amount output in transaction id=" << fill_transaction_hash(tx));
      }

      if(!is_safe_point(boost::get<txout_to_key>(out.target).key))
        return false;
    }
    return true;
  }

  //-----------------------------------------------------------------------------------------------
  bool check_money_overflow(const transaction& tx)
  {
    return check_inputs_overflow(tx) && check_outs_overflow(tx);
  }
  //---------------------------------------------------------------
  bool check_inputs_overflow(const transaction& tx)
  {
    uint64_t money = 0;
    for(const auto& in: tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, tokey_in, false);
      if(money > tokey_in.amount + money)
        return false;
      money += tokey_in.amount;
    }
    return true;
  }
  //---------------------------------------------------------------
  bool check_outs_overflow(const transaction& tx)
  {
    uint64_t money = 0;
    for(const auto& o: tx.vout)
    {
      if(money > o.amount + money)
        return false;
      money += o.amount;
    }
    return true;
  }
  //---------------------------------------------------------------
  uint64_t get_outs_money_amount(const transaction& tx)
  {
    uint64_t outputs_amount = 0;
    for(const auto& o: tx.vout)
      outputs_amount += o.amount;
    return outputs_amount;
  }

  //---------------------------------------------------------------
  blobdata get_block_hashing_blob_tail(const block& b)
  {
    blobdata blob;
    crypto::hash tree_root_hash = get_tx_tree_hash(b);
    blob.append(epee::string_tools::blob_to_string(tree_root_hash.data));
    blob.append(tools::get_varint_data(b.tx_hashes.size()+1));
    return blob;
  }
  //---------------------------------------------------------------
  blobdata get_block_hashing_blob_head(const block& b)
  {
    blobdata blob = t_serializable_object_to_blob(static_cast<block_header>(b));
    return blob;
  }
  //---------------------------------------------------------------
  blobdata get_block_hashing_blob(const block& b)
  {
    return get_block_hashing_blob_head(b).append(get_block_hashing_blob_tail(b));
  }

  //---------------------------------------------------------------
  crypto::hash calculate_block_hash(const block& b)
  {
    return get_object_hash(get_block_hashing_blob(b));
  }

  std::optional<crypto::hash> get_maybe_block_hash(const block& b) {
    crypto::hash h;
    try {
      h = get_block_hash(b);
    }
    catch (...) { return {}; }

    return h;
  }
  //---------------------------------------------------------------
  crypto::hash get_block_hash(const block& b)
  {
    return calculate_block_hash(b);
  }

  //---------------------------------------------------------------
  std::vector<crypto::public_key> get_additional_tx_pub_keys_from_extra(const std::vector<uint8_t>& tx_extra)
  {
    const auto maybe_tx_extra_fields = parse_tx_extra(tx_extra);

    if (!maybe_tx_extra_fields) return {};

    // find corresponding field
    tx_extra_additional_pub_keys additional_pub_keys;
    if(!find_tx_extra_field_by_type(*maybe_tx_extra_fields, additional_pub_keys))
      return {};

    return additional_pub_keys.data;
  }
  //---------------------------------------------------------------
  std::vector<crypto::public_key> get_additional_tx_pub_keys_from_extra(const transaction_prefix& tx)
  {
    return get_additional_tx_pub_keys_from_extra(tx.extra);
  }
}
