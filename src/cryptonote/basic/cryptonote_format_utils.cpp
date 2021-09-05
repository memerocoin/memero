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

#include "cryptonote_format_utils.h"

#include "tools/epee/include/string_tools.h"
#include "tools/serialization/string.h" // don't remove, or face core dump

#include "math/ringct/pseudo_functional/rctSigs.hpp"

#include "wallet/device/functional/device_default.hpp"

#include <boost/algorithm/string.hpp>


using namespace epee;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "cn"

// #define ENABLE_HASH_CASH_INTEGRITY_CHECK

using namespace crypto;
using namespace constant;

static std::atomic<unsigned int> default_decimal_point(CRYPTONOTE_DISPLAY_DECIMAL_POINT);

static std::atomic<uint64_t> tx_hashes_calculated_count(0);
static std::atomic<uint64_t> tx_hashes_cached_count(0);
static std::atomic<uint64_t> block_hashes_calculated_count(0);
static std::atomic<uint64_t> block_hashes_cached_count(0);

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
  bool expand_transaction_1(transaction &tx, bool base_only)
  {
    if (tx.version < 2) return true;
    if (is_coinbase(tx)) return true;

    rct::rctSig &rv = tx.rct_signatures;
    if (rv.type == rct::RCTTypeNull)
      return true;

    if (rv.outPk.size() != tx.vout.size())
    {
      LOG_PRINT_L1("Failed to parse transaction from blob, bad outPk size in tx " << get_transaction_hash(tx));
      return false;
    }

    for (size_t n = 0; n < tx.rct_signatures.outPk.size(); ++n)
    {
      if (tx.vout[n].target.type() != typeid(txout_to_key))
      {
        LOG_PRINT_L1("Unsupported output type in tx " << get_transaction_hash(tx));
        return false;
      }
      rv.outPk[n].dest = rct::pk2rct_p(boost::get<txout_to_key>(tx.vout[n].target).key);
    }

    if (base_only) return true;

    if (rv.p.bulletproofs.size() != 1)
    {
      LOG_PRINT_L1("Failed to parse transaction from blob, bad bulletproofs size in tx " << get_transaction_hash(tx));
      return false;
    }

    if (rv.p.bulletproofs[0].L.size() < 6)
    {
      LOG_PRINT_L1("Failed to parse transaction from blob, bad bulletproofs L size in tx " << get_transaction_hash(tx));
      return false;
    }

    const size_t max_outputs = 1 << (rv.p.bulletproofs[0].L.size() - 6);
    if (max_outputs < tx.vout.size())
    {
      LOG_PRINT_L1("Failed to parse transaction from blob, bad bulletproofs max outputs in tx " << get_transaction_hash(tx));
      return false;
    }

    const size_t n_amounts = tx.vout.size();
    LOG_ERROR_AND_RETURN_UNLESS(n_amounts == rv.outPk.size(), false, "Internal error filling out V");

    std::transform
      (
       rv.outPk.begin()
       , rv.outPk.end()
       , std::back_inserter(rv.p.bulletproofs[0].V)
       , [](const auto& x) {
         return x.commit_of_amount ^ rct::s_inv_eight;
       }
       );

    return true;
  }

  //---------------------------------------------------------------
  bool parse_and_validate_tx_from_blob(const blobdata_ref& tx_blob, transaction& tx)
  {
    std::stringstream ss;
    ss << tx_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, tx);
    LOG_ERROR_AND_RETURN_UNLESS(r, false, "Failed to parse transaction from blob");
    LOG_ERROR_AND_RETURN_UNLESS(expand_transaction_1(tx, false), false, "Failed to expand transaction data");
    tx.invalidate_hashes();
    tx.set_blob_size(tx_blob.size());
    return true;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_tx_base_from_blob(const blobdata_ref& tx_blob, transaction& tx)
  {
    std::stringstream ss;
    ss << tx_blob;
    binary_archive<false> ba(ss);
    bool r = tx.serialize_base(ba);
    LOG_ERROR_AND_RETURN_UNLESS(r, false, "Failed to parse transaction from blob");
    LOG_ERROR_AND_RETURN_UNLESS(expand_transaction_1(tx, true), false, "Failed to expand transaction data");
    tx.invalidate_hashes();
    return true;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_tx_prefix_from_blob(const blobdata_ref& tx_blob, transaction_prefix& tx)
  {
    std::stringstream ss;
    ss << tx_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize_noeof(ba, tx);
    LOG_ERROR_AND_RETURN_UNLESS(r, false, "Failed to parse transaction prefix from blob");
    return true;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_tx_from_blob(const blobdata_ref& tx_blob, transaction& tx, crypto::hash& tx_hash)
  {
    std::stringstream ss;
    ss << tx_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, tx);
    LOG_ERROR_AND_RETURN_UNLESS(r, false, "Failed to parse transaction from blob");
    LOG_ERROR_AND_RETURN_UNLESS(expand_transaction_1(tx, false), false, "Failed to expand transaction data");
    tx.invalidate_hashes();
    //TODO: validate tx

    return get_transaction_hash(tx, tx_hash);
  }
  //---------------------------------------------------------------
  bool parse_and_validate_tx_from_blob(const blobdata_ref& tx_blob, transaction& tx, crypto::hash& tx_hash, crypto::hash& tx_prefix_hash)
  {
    if (!parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash))
      return false;
    tx_prefix_hash = get_transaction_prefix_hash(tx);
    return true;
  }
  //---------------------------------------------------------------
  bool is_v1_tx(const blobdata_ref& tx_blob)
  {
    uint64_t version;
    const char* begin = static_cast<const char*>(tx_blob.data());
    const char* end = begin + tx_blob.size();
    int read = tools::read_varint(begin, end, version);
    if (read <= 0)
      throw std::runtime_error("Internal error getting transaction version");
    return version <= 1;
  }
  //---------------------------------------------------------------
  bool is_v1_tx(const blobdata& tx_blob)
  {
    return is_v1_tx(blobdata_ref{tx_blob.data(), tx_blob.size()});
  }
  //---------------------------------------------------------------
  bool derive_key_image_helper(const account_keys& ack, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, const crypto::public_key& out_key, const crypto::public_key& tx_public_key, const std::vector<crypto::public_key>& additional_tx_public_keys, size_t real_output_index, keypair& in_ephemeral, crypto::key_image& ki)
  {
    const std::optional<crypto::tx_ecdh_shared_secret> recv_tx_shared_secret =
      crypto::derive_tx_ecdh_shared_secret(tx_public_key, ack.m_view_secret_key);

    if (!recv_tx_shared_secret)
    {
      LOG_WARNING("key image helper: failed to derive_tx_ecdh_shared_secret(" << tx_public_key << ", " << ack.m_view_secret_key << ")");
      return false;
    }

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
       subaddresses, out_key, *recv_tx_shared_secret, additional_recv_tx_shared_secrets, real_output_index
       );

    LOG_ERROR_AND_RETURN_UNLESS
      (
       subaddr_recv_info
       , false
       , "key image helper: given output pubkey doesn't seem to belong to this address"
       );

    return derive_key_image_helper_precomp
      (
       ack
       , out_key
       , subaddr_recv_info->tx_shared_secret
       , real_output_index
       , subaddr_recv_info->index
       , in_ephemeral
       , ki
       );
  }

  //---------------------------------------------------------------
  bool derive_key_image_helper_precomp(const account_keys& ack, const crypto::public_key& out_key, const crypto::tx_ecdh_shared_secret& recv_tx_shared_secret, size_t real_output_index, const subaddress_index& received_index, keypair& in_ephemeral, crypto::key_image& ki)
  {
    if (ack.m_spend_secret_key == crypto::null_skey)
    {
      // for watch-only wallet, simply copy the known output pubkey
      in_ephemeral.pub = out_key;
      in_ephemeral.sec = crypto::null_skey;
    }
    else
    {
      // derive secret key with subaddress - step 1: original CN derivation
      const crypto::secret_key scalar_step1 =
        derive_secret_key(recv_tx_shared_secret, real_output_index, ack.m_spend_secret_key);
      // computes Hs(a*R || idx) + b

      // step 2: add Hs(a || index_major || index_minor)
      crypto::secret_key subaddr_sk;
      crypto::secret_key scalar_step2;
      if (received_index.is_zero())
      {
        scalar_step2 = scalar_step1;    // treat index=(0,0) as a special case representing the main address
      }
      else
      {
        subaddr_sk = device::get_subaddress_secret_key(ack.m_view_secret_key, received_index);
        scalar_step2 = s2sk(scalar_step1 + subaddr_sk);
      }

      in_ephemeral.sec = scalar_step2;
      in_ephemeral.pub = to_pk(in_ephemeral.sec);

      LOG_ERROR_AND_RETURN_UNLESS(in_ephemeral.pub == out_key,
           false, "key image helper precomp: given output pubkey doesn't match the derived one");
    }

    ki = crypto::derive_key_image(in_ephemeral.pub, in_ephemeral.sec);
    return true;
  }

  //---------------------------------------------------------------
  bool parse_amount(uint64_t& amount, const std::string& str_amount_)
  {
    std::string str_amount = str_amount_;
    boost::algorithm::trim(str_amount);

    size_t point_index = str_amount.find_first_of('.');
    size_t fraction_size;
    if (std::string::npos != point_index)
    {
      fraction_size = str_amount.size() - point_index - 1;
      while (default_decimal_point < fraction_size && '0' == str_amount.back())
      {
        str_amount.erase(str_amount.size() - 1, 1);
        --fraction_size;
      }
      if (default_decimal_point < fraction_size)
        return false;
      str_amount.erase(point_index, 1);
    }
    else
    {
      fraction_size = 0;
    }

    if (str_amount.empty())
      return false;

    if (fraction_size < default_decimal_point)
    {
      str_amount.append(default_decimal_point - fraction_size, '0');
    }

    return epee::string_tools::get_xtype_from_string(amount, str_amount);
  }
  //---------------------------------------------------------------
  uint64_t get_transaction_weight(const transaction &tx, size_t blob_size)
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
      return tx.rct_signatures.txnFee;
    }
    else return 0;
  }
  //---------------------------------------------------------------
  bool parse_tx_extra(const std::vector<uint8_t>& tx_extra, std::vector<tx_extra_field>& tx_extra_fields)
  {
    tx_extra_fields.clear();

    if(tx_extra.empty())
      return true;

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
         , false
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
       , false
       , "failed to deserialize extra field. extra = "
       << epee::string_tools::buff_to_hex_nodelimer(epee::string_tools::blob_to_string(tx_extra))
       );
    return true;
  }
  //---------------------------------------------------------------
  template<typename T>
  static bool pick(binary_archive<true> &ar, std::vector<tx_extra_field> &fields, uint8_t tag)
  {
    std::vector<tx_extra_field>::iterator it;
    while ((it = std::find_if(fields.begin(), fields.end(), [](const tx_extra_field &f) { return f.type() == typeid(T); })) != fields.end())
    {
      bool r = ::do_serialize(ar, tag);
      LOG_WITH_LEVEL_1_AND_RETURN_UNLESS(r, false, "failed to serialize tx extra field");
      r = ::do_serialize(ar, boost::get<T>(*it));
      LOG_WITH_LEVEL_1_AND_RETURN_UNLESS(r, false, "failed to serialize tx extra field");
      fields.erase(it);
    }
    return true;
  }
  //---------------------------------------------------------------
  bool sort_tx_extra(const std::vector<uint8_t>& tx_extra, std::vector<uint8_t> &sorted_tx_extra, bool allow_partial)
  {
    std::vector<tx_extra_field> tx_extra_fields;

    if(tx_extra.empty())
    {
      sorted_tx_extra.clear();
      return true;
    }

    std::string extra_str = epee::string_tools::blob_to_string(tx_extra);
    std::istringstream iss(extra_str);
    binary_archive<false> ar(iss);

    bool eof = false;
    size_t processed = 0;
    while (!eof)
    {
      tx_extra_field field;
      bool r = ::do_serialize(ar, field);
      if (!r)
      {
        LOG_DEBUG
          (
           "failed to deserialize extra field. extra = "
           << epee::string_tools::buff_to_hex_nodelimer(epee::string_tools::blob_to_string(tx_extra))
           );

        if (!allow_partial)
          return false;
        break;
      }
      tx_extra_fields.push_back(field);
      processed = iss.tellg();

      std::ios_base::iostate state = iss.rdstate();
      eof = (EOF == iss.peek());
      iss.clear(state);
    }
    if (!::serialization::check_stream_state(ar))
    {
      LOG_DEBUG
        (
         "failed to deserialize extra field. extra = "
         << epee::string_tools::buff_to_hex_nodelimer(epee::string_tools::blob_to_string(tx_extra))
         );
      if (!allow_partial)
        return false;
    }
    LOG_TRACE("Sorted " << processed << "/" << tx_extra.size());

    std::ostringstream oss;
    binary_archive<true> nar(oss);

    // sort by:
    if (!pick<tx_extra_pub_key>(nar, tx_extra_fields, TX_EXTRA_TAG_PUBKEY)) return false;
    if (!pick<tx_extra_additional_pub_keys>(nar, tx_extra_fields, TX_EXTRA_TAG_ADDITIONAL_PUBKEYS)) return false;

    // if not empty, someone added a new type and did not add a case above
    if (!tx_extra_fields.empty())
    {
      LOG_ERROR("tx_extra_fields not empty after sorting, someone forgot to add a case above");
      return false;
    }

    std::string oss_str = oss.str();
    if (allow_partial && processed < tx_extra.size())
    {
      LOG_DEBUG("Appending unparsed data");
      oss_str += epee::string_tools::blob_to_string(std::span(tx_extra).subspan(processed, tx_extra.size() - processed));
    }
    sorted_tx_extra = std::vector<uint8_t>(oss_str.begin(), oss_str.end());
    return true;
  }
  //---------------------------------------------------------------
  crypto::public_key get_tx_pub_key_from_extra(const std::vector<uint8_t>& tx_extra, size_t pk_index)
  {
    std::vector<tx_extra_field> tx_extra_fields;
    parse_tx_extra(tx_extra, tx_extra_fields);

    tx_extra_pub_key pub_key_field;
    if(!find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, pk_index))
      return null_pkey;

    return pub_key_field.pub_key;
  }
  //---------------------------------------------------------------
  crypto::public_key get_tx_pub_key_from_extra(const transaction_prefix& tx_prefix, size_t pk_index)
  {
    return get_tx_pub_key_from_extra(tx_prefix.extra, pk_index);
  }
  //---------------------------------------------------------------
  crypto::public_key get_tx_pub_key_from_extra(const transaction& tx, size_t pk_index)
  {
    return get_tx_pub_key_from_extra(tx.extra, pk_index);
  }
  //---------------------------------------------------------------
  bool add_tx_pub_key_to_extra(transaction& tx, const crypto::public_key& tx_pub_key)
  {
    return add_tx_pub_key_to_extra(tx.extra, tx_pub_key);
  }
  //---------------------------------------------------------------
  bool add_tx_pub_key_to_extra(transaction_prefix& tx, const crypto::public_key& tx_pub_key)
  {
    return add_tx_pub_key_to_extra(tx.extra, tx_pub_key);
  }
  //---------------------------------------------------------------
  bool add_tx_pub_key_to_extra(std::vector<uint8_t>& tx_extra, const crypto::public_key& tx_pub_key)
  {
    tx_extra.push_back(TX_EXTRA_TAG_PUBKEY);
    tx_extra.insert(tx_extra.end(), tx_pub_key.data.begin(), tx_pub_key.data.end());
    return true;
  }
  //---------------------------------------------------------------
  std::vector<crypto::public_key> get_additional_tx_pub_keys_from_extra(const std::vector<uint8_t>& tx_extra)
  {
    // parse
    std::vector<tx_extra_field> tx_extra_fields;
    parse_tx_extra(tx_extra, tx_extra_fields);
    // find corresponding field
    tx_extra_additional_pub_keys additional_pub_keys;
    if(!find_tx_extra_field_by_type(tx_extra_fields, additional_pub_keys))
      return {};
    return additional_pub_keys.data;
  }
  //---------------------------------------------------------------
  std::vector<crypto::public_key> get_additional_tx_pub_keys_from_extra(const transaction_prefix& tx)
  {
    return get_additional_tx_pub_keys_from_extra(tx.extra);
  }
  //---------------------------------------------------------------
  bool add_additional_tx_pub_keys_to_extra(std::vector<uint8_t>& tx_extra, const std::vector<crypto::public_key>& additional_pub_keys)
  {
    // convert to variant
    tx_extra_field field = tx_extra_additional_pub_keys{ additional_pub_keys };
    // serialize
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    bool r = ::do_serialize(ar, field);
    LOG_WITH_LEVEL_1_AND_RETURN_UNLESS(r, false, "failed to serialize tx extra additional tx pub keys");

    // append
    std::string tx_extra_str = oss.str();
    std::copy(tx_extra_str.begin(), tx_extra_str.end(), std::back_inserter(tx_extra));
    return true;
  }
  //---------------------------------------------------------------
  bool remove_field_from_tx_extra(std::vector<uint8_t>& tx_extra, const std::type_info &type)
  {
    if (tx_extra.empty())
      return true;
    std::string extra_str = epee::string_tools::blob_to_string(tx_extra);
    std::istringstream iss(extra_str);
    binary_archive<false> ar(iss);
    std::ostringstream oss;
    binary_archive<true> newar(oss);

    bool eof = false;
    while (!eof)
    {
      tx_extra_field field;
      bool r = ::do_serialize(ar, field);
      LOG_WITH_LEVEL_2_AND_RETURN_UNLESS
        (
         r
         , false
         , "failed to deserialize extra field. extra = "
         << epee::string_tools::buff_to_hex_nodelimer(epee::string_tools::blob_to_string(tx_extra))
         );
      if (field.type() != type)
        ::do_serialize(newar, field);

      std::ios_base::iostate state = iss.rdstate();
      eof = (EOF == iss.peek());
      iss.clear(state);
    }
    LOG_WITH_LEVEL_2_AND_RETURN_UNLESS
      (
       ::serialization::check_stream_state(ar)
       , false
       , "failed to deserialize extra field. extra = "
       << epee::string_tools::buff_to_hex_nodelimer(epee::string_tools::blob_to_string(tx_extra))
       );
    tx_extra.clear();
    std::string s = oss.str();
    tx_extra.reserve(s.size());
    std::copy(s.begin(), s.end(), std::back_inserter(tx_extra));
    return true;
  }
  //---------------------------------------------------------------
  bool get_inputs_money_amount(const transaction& tx, uint64_t& money)
  {
    money = 0;
    for(const auto& in: tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, tokey_in, false);
      money += tokey_in.amount;
    }
    return true;
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
      LOG_ERROR_AND_RETURN_UNLESS(in.type() == typeid(txin_to_key), false, "wrong variant type: "
        << in.type().name() << ", expected " << typeid(txin_to_key).name()
        << ", in transaction id=" << get_transaction_hash(tx));

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
        << ", in transaction id=" << get_transaction_hash(tx));

      if (tx.version == 1)
      {
        LOG_WITH_LEVEL_0_AND_RETURN_UNLESS(0 < out.amount, false, "zero amount output in transaction id=" << get_transaction_hash(tx));
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
  std::string short_hash_str(const crypto::hash& h)
  {
    std::string res = epee::string_tools::pod_to_hex(h);
    LOG_ERROR_AND_RETURN_UNLESS(res.size() == 64, res, "wrong hash256 with epee::string_tools::pod_to_hex conversion");
    auto erased_pos = res.erase(8, 48);
    res.insert(8, "....");
    return res;
  }
  //---------------------------------------------------------------
  bool is_out_to_acc(const account_keys& acc, const txout_to_key& out_key, const crypto::public_key& tx_pub_key, const std::vector<crypto::public_key>& additional_tx_pub_keys, size_t output_index)
  {
    const std::optional<crypto::tx_ecdh_shared_secret> derivation =
      crypto::derive_tx_ecdh_shared_secret(tx_pub_key, acc.m_view_secret_key);
    LOG_ERROR_AND_RETURN_UNLESS(derivation, false, "Failed to generate key derivation");

    const std::optional<crypto::public_key> pk =
      crypto::derive_tx_output_public_key(*derivation, output_index, acc.m_account_address.m_spend_public_key);

    LOG_ERROR_AND_RETURN_UNLESS(pk, false, "Failed to derive public key");
    if (*pk == out_key.key) {
      return true;
    }
    // try additional tx pubkeys if available
    if (!additional_tx_pub_keys.empty())
    {
      LOG_ERROR_AND_RETURN_UNLESS(output_index < additional_tx_pub_keys.size(), false, "wrong number of additional tx pubkeys");

      const auto kd = crypto::derive_tx_ecdh_shared_secret(additional_tx_pub_keys[output_index], acc.m_view_secret_key);
      LOG_ERROR_AND_RETURN_UNLESS(kd, false, "Failed to generate key derivation");

      const auto tx_out_pk = crypto::derive_tx_output_public_key(*derivation, output_index, acc.m_account_address.m_spend_public_key);
      LOG_ERROR_AND_RETURN_UNLESS(tx_out_pk, false, "Failed to derive public key");

      return *tx_out_pk == out_key.key;
    }
    return false;
  }

  //---------------------------------------------------------------
  std::optional<subaddress_receive_info> is_out_to_acc_precomp(const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, const crypto::public_key& out_key, const crypto::tx_ecdh_shared_secret& derivation, const std::vector<crypto::tx_ecdh_shared_secret>& tx_shared_secrets, size_t output_index)
  {
    // try the shared tx pubkey
    const std::optional<crypto::public_key> subaddress_spendkey = crypto::derive_subaddress_public_key(out_key, derivation, output_index);
    auto found = subaddresses.find(subaddress_spendkey.value_or(crypto::null_pkey));
    if (found != subaddresses.end())
      return subaddress_receive_info{ found->second, derivation };
    // try additional tx pubkeys if available
    if (!tx_shared_secrets.empty())
    {
      LOG_ERROR_AND_RETURN_UNLESS(output_index < tx_shared_secrets.size(), std::nullopt, "wrong number of additional derivations");
      const auto sub_pk = crypto::derive_subaddress_public_key(out_key, tx_shared_secrets[output_index], output_index);
      found = subaddresses.find(sub_pk.value_or(crypto::null_pkey));
      if (found != subaddresses.end())
        return subaddress_receive_info{ found->second, tx_shared_secrets[output_index] };
    }
    return {};
  }
  //---------------------------------------------------------------
  bool lookup_acc_outs(const account_keys& acc, const transaction& tx, std::vector<size_t>& outs, uint64_t& money_transfered)
  {
    crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
    if(null_pkey == tx_pub_key)
      return false;
    std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(tx);
    return lookup_acc_outs(acc, tx, tx_pub_key, additional_tx_pub_keys, outs, money_transfered);
  }
  //---------------------------------------------------------------
  bool lookup_acc_outs(const account_keys& acc, const transaction& tx, const crypto::public_key& tx_pub_key, const std::vector<crypto::public_key>& additional_tx_pub_keys, std::vector<size_t>& outs, uint64_t& money_transfered)
  {
    LOG_ERROR_AND_RETURN_UNLESS(additional_tx_pub_keys.empty() || additional_tx_pub_keys.size() == tx.vout.size(), false, "wrong number of additional pubkeys" );
    money_transfered = 0;
    size_t i = 0;
    for(const tx_out& o:  tx.vout)
    {
      LOG_ERROR_AND_RETURN_UNLESS(o.target.type() ==  typeid(txout_to_key), false, "wrong type id in transaction out" );
      if(is_out_to_acc(acc, boost::get<txout_to_key>(o.target), tx_pub_key, additional_tx_pub_keys, i))
      {
        outs.push_back(i);
        money_transfered += o.amount;
      }
      i++;
    }
    return true;
  }
  //---------------------------------------------------------------
  crypto::hash get_blob_hash(const blobdata_ref& blob)
  {
    return sha3(epee::string_tools::string_view_to_blob_view(blob));
  }
  //---------------------------------------------------------------
  crypto::hash get_blob_hash(const blobdata& blob)
  {
    return sha3(epee::string_tools::string_to_blob(blob));
  }
  //---------------------------------------------------------------
  void set_default_decimal_point(unsigned int decimal_point)
  {
    switch (decimal_point)
    {
      case 11:
      case 9:
      case 6:
      case 3:
      case 0:
        default_decimal_point = decimal_point;
        break;
      default:
        LOG_ERROR_AND_THROW("Invalid decimal point specification: " << decimal_point);
    }
  }
  //---------------------------------------------------------------
  unsigned int get_default_decimal_point()
  {
    return default_decimal_point;
  }
  //---------------------------------------------------------------
  std::string get_unit(unsigned int decimal_point)
  {
    if (decimal_point == (unsigned int)-1)
      decimal_point = default_decimal_point;
    switch (decimal_point)
    {
      case 11:
        return "lolnero";
      case 9:
        return "millinero";
      case 6:
        return "micronero";
      case 3:
        return "nanonero";
      case 0:
        return "piconero";
      default:
        LOG_ERROR_AND_THROW("Invalid decimal point specification: " << decimal_point);
    }
  }
  //---------------------------------------------------------------
  static void insert_money_decimal_point(std::string &s, unsigned int decimal_point)
  {
    if (decimal_point == (unsigned int)-1)
      decimal_point = default_decimal_point;
    if(s.size() < decimal_point+1)
    {
      s.insert(0, decimal_point+1 - s.size(), '0');
    }
    if (decimal_point > 0)
      s.insert(s.size() - decimal_point, ".");
  }
  //---------------------------------------------------------------
  std::string print_money_64(uint64_t amount, unsigned int decimal_point)
  {
    std::string s = std::to_string(amount);
    insert_money_decimal_point(s, decimal_point);
    return s;
  }
  //---------------------------------------------------------------
  std::string print_money(uint64_t amount, unsigned int decimal_point)
  {
    std::string str = print_money_64(amount, decimal_point);
    str.erase ( str.find_last_not_of('0') + 1, std::string::npos );
    str.erase ( str.find_last_not_of('.') + 1, std::string::npos );
    return str;
  }
  //---------------------------------------------------------------
  std::string print_money_128(const boost::multiprecision::uint128_t &amount, unsigned int decimal_point)
  {
    std::stringstream ss;
    ss << amount;
    std::string s = ss.str();
    insert_money_decimal_point(s, decimal_point);
    return s;
  }
  //---------------------------------------------------------------
  std::string print_money(const boost::multiprecision::uint128_t &amount, unsigned int decimal_point)
  {
    std::string str = print_money_128(amount, decimal_point);
    str.erase ( str.find_last_not_of('0') + 1, std::string::npos );
    str.erase ( str.find_last_not_of('.') + 1, std::string::npos );
    return str;
  }
  //---------------------------------------------------------------
  crypto::hash get_transaction_hash(const transaction& t)
  {
    crypto::hash h = null_hash;
    get_transaction_hash(t, h, NULL);
    LOG_ERROR_AND_THROW_UNLESS(get_transaction_hash(t, h, NULL), "Failed to calculate transaction hash");
    return h;
  }
  //---------------------------------------------------------------
  bool get_transaction_hash(const transaction& t, crypto::hash& res)
  {
    return get_transaction_hash(t, res, NULL);
  }
  //---------------------------------------------------------------
  bool calculate_transaction_prunable_hash(const transaction& t, const cryptonote::blobdata_ref *blob, crypto::hash& res)
  {
    if (t.version == 1)
      return false;
    const unsigned int unprunable_size = t.unprunable_size;
    if (blob && unprunable_size)
    {
      LOG_ERROR_AND_RETURN_UNLESS(unprunable_size <= blob->size(), false, "Inconsistent transaction unprunable and blob sizes");
      res = cryptonote::get_blob_hash(blobdata_ref(blob->data() + unprunable_size, blob->size() - unprunable_size));
    }
    else
    {
      transaction &tt = const_cast<transaction&>(t);
      std::stringstream ss;
      binary_archive<true> ba(ss);
      const size_t inputs = t.vin.size();
      const size_t outputs = t.vout.size();
      const size_t mixin = t.vin.empty() ? 0 : t.vin[0].type() == typeid(txin_to_key) ? boost::get<txin_to_key>(t.vin[0]).key_offsets.size() - 1 : 0;
      bool r = tt.rct_signatures.p.serialize_rctsig_prunable(ba, t.rct_signatures.type, inputs, outputs, mixin);
      LOG_ERROR_AND_RETURN_UNLESS(r, false, "Failed to serialize rct signatures prunable");
      res = cryptonote::get_blob_hash(ss.str());
    }
    return true;
  }
  //---------------------------------------------------------------
  crypto::hash get_transaction_prunable_hash(const transaction& t, const cryptonote::blobdata_ref *blobdata)
  {
    crypto::hash res;
    if (t.is_prunable_hash_valid())
    {
#ifdef ENABLE_HASH_CASH_INTEGRITY_CHECK
      LOG_ERROR_AND_THROW_UNLESS(!calculate_transaction_prunable_hash(t, blobdata, res) || t.hash == res, "tx hash cash integrity failure");
#endif
      res = t.prunable_hash;
      ++tx_hashes_cached_count;
      return res;
    }

    ++tx_hashes_calculated_count;
    LOG_ERROR_AND_THROW_UNLESS(calculate_transaction_prunable_hash(t, blobdata, res), "Failed to calculate tx prunable hash");
    t.set_prunable_hash(res);
    return res;
  }
  //---------------------------------------------------------------
  bool calculate_transaction_hash(const transaction& t, crypto::hash& res, size_t* blob_size)
  {
    // v1 transactions hash the entire blob
    if (t.version == 1)
    {
      size_t ignored_blob_size, &blob_size_ref = blob_size ? *blob_size : ignored_blob_size;
      return get_object_hash(t, res, blob_size_ref);
    }

    // v2 transactions hash different parts together, than hash the set of those hashes
    crypto::hash hashes[3];

    // prefix
    hashes[0] = get_transaction_prefix_hash(t);

    const blobdata blob = tx_to_blob(t);
    const unsigned int unprunable_size = t.unprunable_size;
    const unsigned int prefix_size = t.prefix_size;

    // base rct
    LOG_ERROR_AND_RETURN_UNLESS(prefix_size <= unprunable_size && unprunable_size <= blob.size(), false, "Inconsistent transaction prefix, unprunable and blob sizes");
    hashes[1] = cryptonote::get_blob_hash(blobdata_ref(blob.data() + prefix_size, unprunable_size - prefix_size));

    // prunable rct
    if (t.rct_signatures.type == rct::RCTTypeNull)
    {
      hashes[2] = crypto::null_hash;
    }
    else
    {
      cryptonote::blobdata_ref blobref(blob);
      LOG_ERROR_AND_RETURN_UNLESS(calculate_transaction_prunable_hash(t, &blobref, hashes[2]), false, "Failed to get tx prunable hash");
    }

    // the tx hash is the hash of the 3 hashes
    res = sha3(epee::blob::span((const uint8_t*)hashes, sizeof(hashes)));

    // we still need the size
    if (blob_size)
    {
      if (!t.is_blob_size_valid())
      {
        t.set_blob_size(blob.size());
      }
      *blob_size = t.blob_size;
    }

    return true;
  }
  //---------------------------------------------------------------
  bool get_transaction_hash(const transaction& t, crypto::hash& res, size_t* blob_size)
  {
    if (t.is_hash_valid())
    {
#ifdef ENABLE_HASH_CASH_INTEGRITY_CHECK
      LOG_ERROR_AND_THROW_UNLESS(!calculate_transaction_hash(t, res, blob_size) || t.hash == res, "tx hash cash integrity failure");
#endif
      res = t.hash;
      if (blob_size)
      {
        if (!t.is_blob_size_valid())
        {
          t.set_blob_size(get_object_blobsize(t));
        }
        *blob_size = t.blob_size;
      }
      ++tx_hashes_cached_count;
      return true;
    }
    ++tx_hashes_calculated_count;
    bool ret = calculate_transaction_hash(t, res, blob_size);
    if (!ret)
      return false;
    t.set_hash(res);
    if (blob_size)
    {
      t.set_blob_size(*blob_size);
    }
    return true;
  }
  //---------------------------------------------------------------
  bool get_transaction_hash(const transaction& t, crypto::hash& res, size_t& blob_size)
  {
    return get_transaction_hash(t, res, &blob_size);
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
  bool calculate_block_hash(const block& b, crypto::hash& res, const blobdata_ref *blob)
  {
    return get_object_hash(get_block_hashing_blob(b), res);
  }
  //---------------------------------------------------------------
  bool get_block_hash(const block& b, crypto::hash& res)
  {
    if (b.is_hash_valid())
    {
#ifdef ENABLE_HASH_CASH_INTEGRITY_CHECK
      LOG_ERROR_AND_THROW_UNLESS(!calculate_block_hash(b, res) || b.hash == res, "block hash cash integrity failure");
#endif
      res = b.hash;
      ++block_hashes_cached_count;
      return true;
    }
    ++block_hashes_calculated_count;
    bool ret = calculate_block_hash(b, res);
    if (!ret)
      return false;
    b.set_hash(res);
    return true;
  }
  //---------------------------------------------------------------
  crypto::hash get_block_hash(const block& b)
  {
    crypto::hash p = null_hash;
    get_block_hash(b, p);
    return p;
  }
  //---------------------------------------------------------------
  std::vector<uint64_t> relative_output_offsets_to_absolute(const std::vector<uint64_t>& off)
  {
    std::vector<uint64_t> res = off;
    for(size_t i = 1; i < res.size(); i++)
      res[i] += res[i-1];
    return res;
  }
  //---------------------------------------------------------------
  std::vector<uint64_t> absolute_output_offsets_to_relative(const std::vector<uint64_t>& off)
  {
    std::vector<uint64_t> res = off;
    if(!off.size())
      return res;
    std::sort(res.begin(), res.end());//just to be sure, actually it is already should be sorted
    for(size_t i = res.size()-1; i != 0; i--)
      res[i] -= res[i-1];

    return res;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_block_from_blob(const blobdata_ref& b_blob, block& b, crypto::hash *block_hash)
  {
    std::stringstream ss;
    ss << b_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, b);
    LOG_ERROR_AND_RETURN_UNLESS(r, false, "Failed to parse block from blob");
    b.invalidate_hashes();
    b.miner_tx.invalidate_hashes();
    if (block_hash)
    {
      calculate_block_hash(b, *block_hash, &b_blob);
      ++block_hashes_calculated_count;
      b.set_hash(*block_hash);
    }
    return true;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_block_from_blob(const blobdata_ref& b_blob, block& b)
  {
    return parse_and_validate_block_from_blob(b_blob, b, NULL);
  }
  //---------------------------------------------------------------
  bool parse_and_validate_block_from_blob(const blobdata_ref& b_blob, block& b, crypto::hash &block_hash)
  {
    return parse_and_validate_block_from_blob(b_blob, b, &block_hash);
  }
  //---------------------------------------------------------------
  blobdata block_to_blob(const block& b)
  {
    return t_serializable_object_to_blob(b);
  }
  //---------------------------------------------------------------
  bool block_to_blob(const block& b, blobdata& b_blob)
  {
    return t_serializable_object_to_blob(b, b_blob);
  }
  //---------------------------------------------------------------
  blobdata tx_to_blob(const transaction& tx)
  {
    return t_serializable_object_to_blob(tx);
  }
  //---------------------------------------------------------------
  bool tx_to_blob(const transaction& tx, blobdata& b_blob)
  {
    return t_serializable_object_to_blob(tx, b_blob);
  }
  //---------------------------------------------------------------
  void get_tx_tree_hash(const std::vector<crypto::hash>& tx_hashes, crypto::hash& h)
  {
    h = tree_hash(tx_hashes);
  }
  //---------------------------------------------------------------
  crypto::hash get_tx_tree_hash(const std::vector<crypto::hash>& tx_hashes)
  {
    crypto::hash h = null_hash;
    get_tx_tree_hash(tx_hashes, h);
    return h;
  }
  //---------------------------------------------------------------
  crypto::hash get_tx_tree_hash(const block& b)
  {
    std::vector<crypto::hash> txs_ids;
    txs_ids.reserve(1 + b.tx_hashes.size());
    crypto::hash h = null_hash;
    size_t bl_sz = 0;
    LOG_ERROR_AND_THROW_UNLESS(get_transaction_hash(b.miner_tx, h, bl_sz), "Failed to calculate transaction hash");
    txs_ids.push_back(h);
    for(auto& th: b.tx_hashes)
      txs_ids.push_back(th);
    return get_tx_tree_hash(txs_ids);
  }
  //---------------------------------------------------------------
  void get_hash_stats(uint64_t &tx_hashes_calculated, uint64_t &tx_hashes_cached, uint64_t &block_hashes_calculated, uint64_t & block_hashes_cached)
  {
    tx_hashes_calculated = tx_hashes_calculated_count;
    tx_hashes_cached = tx_hashes_cached_count;
    block_hashes_calculated = block_hashes_calculated_count;
    block_hashes_cached = block_hashes_cached_count;
  }
  //---------------------------------------------------------------
  crypto::secret_key encrypt_key(crypto::secret_key key, const epee::wipeable_string &passphrase)
  {
    crypto::ec_scalar hash = crypto::hash_to_scalar(epee::string_tools::string_to_blob(passphrase));
    key = s2sk(key + hash);
    return key;
  }
  //---------------------------------------------------------------
  crypto::secret_key decrypt_key(crypto::secret_key key, const epee::wipeable_string &passphrase)
  {
    crypto::ec_scalar hash = crypto::hash_to_scalar(epee::string_tools::string_to_blob(passphrase));
    key = s2sk(key - hash);
    return key;
  }
}
