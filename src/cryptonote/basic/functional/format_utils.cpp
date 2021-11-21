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

#include "math/crypto/functional/tree-hash.hpp"
#include "math/ringct/pseudo_functional/ringCT.hpp"
#include "math/ringct/functional/rctOps.hpp"

#include "cryptonote/basic/functional/subaddress.hpp"

#include <boost/algorithm/string.hpp>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "cn"

namespace cryptonote
{
  //---------------------------------------------------------------
  crypto::hash get_transaction_prefix_hash(const transaction_prefix& tx)
  {
    const string_blob bd = t_serializable_object_to_blob(tx);
    return crypto::sha3(epee::string_tools::string_to_blob(bd));
  }

  //---------------------------------------------------------------
  std::optional<std::pair<keypair, crypto::key_image>>
  derive_with_internal_checking_output_key_pair_and_key_image
  (
   const account_keys ack
   , const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses
   , const crypto::public_key out_key
   , const std::optional<crypto::public_key> tx_public_key
   , const std::span<const crypto::public_key> output_public_keys
   , const size_t real_output_index
   )
  {
    const std::optional<crypto::ecdh_shared_secret> output_shared_secret = 
      (real_output_index >= 0 && real_output_index < output_public_keys.size())
      ? std::make_optional
      (
       crypto::derive_tx_output_ecdh_shared_secret
       (
        output_public_keys[real_output_index]
        , ack.m_view_secret_key
        )
       )
      : tx_public_key
      ? std::make_optional(crypto::derive_tx_output_ecdh_shared_secret(*tx_public_key, ack.m_view_secret_key))
      : std::nullopt
      ;

    LOG_ERROR_AND_RETURN_UNLESS
      (
       output_shared_secret
       , {}
       , "failed to generate a valid output shared secret"
       );

    std::optional<subaddress_receive_info> subaddr_recv_info =
      check_output_for_subaddresses
      (
       subaddresses, out_key, *output_shared_secret, real_output_index
       );

    LOG_ERROR_AND_RETURN_UNLESS
      (
       subaddr_recv_info
       , {}
       , "key image helper: given output pubkey doesn't seem to belong to this address"
       );

    return derive_output_key_pair_and_key_image
      (
       ack
       , out_key
       , subaddr_recv_info->tx_output_shared_secret
       , real_output_index
       , subaddr_recv_info->index
       );
  }

  //---------------------------------------------------------------
  std::optional<std::pair<keypair, crypto::key_image>>
  derive_output_key_pair_and_key_image
  (
   const account_keys account_keys
   , const crypto::public_key out_key
   , const crypto::ecdh_shared_secret recv_tx_output_shared_secret
   , const size_t real_output_index
   , const subaddress_index received_index
   )
  {
    const crypto::secret_key spend_sk = get_subaddress_spend_secret_key
      (account_keys.get_spend_view_secret_keys(), received_index);
    const crypto::secret_key output_secret_key =
      compute_output_secret_key_from_subaddress_spend_sk
      (recv_tx_output_shared_secret, real_output_index, spend_sk);

    const keypair output_spend_key =
      {
        output_secret_key
        , to_pk(output_secret_key)
      };

    LOG_ERROR_AND_RETURN_UNLESS(output_spend_key.pub == out_key,
          {}, "key image helper precomp: given output pubkey doesn't match the derived one");

    const crypto::key_image ki =
      crypto::derive_key_image(output_spend_key.sec);

    return {{output_spend_key, ki}};
  }

  //---------------------------------------------------------------
  std::optional<subaddress_receive_info> check_output_for_subaddresses
  (
   const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses
   , const crypto::public_key tx_output_public_key
   , const crypto::ecdh_shared_secret tx_output_shared_secret
   , const size_t output_index
   )
  {
    // try additional tx pubkeys if available
    const auto spend_pk_1 =
      crypto::compute_subaddress_spend_pk_from_output_public_key
      (tx_output_shared_secret, output_index, tx_output_public_key);

    if (spend_pk_1) {
      const auto found_1 = subaddresses.find(*spend_pk_1);

      if (found_1 != subaddresses.end()) {
        // LOG_FATAL("FOUND for out pub key at index: " << output_index);
        return subaddress_receive_info{ found_1->second, tx_output_shared_secret};
      }
    }
    return {};
  }

  //---------------------------------------------------------------
  crypto::hash get_blob_hash(const string_blob_view blob)
  {
    return crypto::sha3(epee::string_tools::string_view_to_blob_view(blob));
  }
  //---------------------------------------------------------------
  crypto::hash get_blob_hash(const string_blob blob)
  {
    return crypto::sha3(epee::string_tools::string_to_blob(blob));
  }

  //---------------------------------------------------------------
  std::string short_hash_str(const crypto::hash h)
  {
    std::string res = epee::string_tools::pod_to_hex(h);
    LOG_ERROR_AND_RETURN_UNLESS
      (res.size() == 64, res, "wrong hash256 with epee::string_tools::pod_to_hex conversion");
    auto erased_pos = res.erase(8, 48);
    res.insert(8, "....");
    return res;
  }

  //---------------------------------------------------------------
  crypto::hash calculate_transaction_prunable_hash
  (
   const transaction& t
   , const cryptonote::string_blob_view blob
   )
  {

    LOG_ERROR_AND_THROW_IF
      (
       t.version == 1
       , "error trying to calculate prunable_hash on v1 tx"
       );

    const unsigned int prefix_and_ringct_basic_size = t.prefix_and_ringct_basic_size;

    LOG_ERROR_AND_THROW_UNLESS
      (
       prefix_and_ringct_basic_size <= blob.size()
       , "Inconsistent transaction unprunable and blob sizes"
       );

    return cryptonote::get_blob_hash
      (
       string_blob_view
       (
        blob.data() + prefix_and_ringct_basic_size
        , blob.size() - prefix_and_ringct_basic_size
        )
       );
  }

  //---------------------------------------------------------------
  crypto::hash get_transaction_hash(const transaction& t)
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

    const string_blob blob = tx_to_blob(t);
    const unsigned int prefix_and_ringct_basic_size = t.prefix_and_ringct_basic_size;
    const unsigned int prefix_size = t.prefix_size;

    // base rct
    if (!
        (
         prefix_size <= prefix_and_ringct_basic_size
           && prefix_and_ringct_basic_size <= blob.size()
         )) {
      LOG_FATAL("Inconsistent transaction prefix, unprunable and blob sizes");
    }

    hashes[1] = cryptonote::get_blob_hash
      (blob.substr(prefix_size, prefix_and_ringct_basic_size - prefix_size));

    // prunable rct
    hashes[2]
      = t.ringct.type == rct::RCTTypeNull
      ? crypto::null_hash
      : calculate_transaction_prunable_hash(t, blob);

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
  crypto::hash get_tx_tree_hash(const std::span<const crypto::hash> tx_hashes)
  {
    return tree_hash(tx_hashes).value_or(crypto::null_hash);
  }
  //---------------------------------------------------------------
  crypto::hash get_tx_tree_hash(const block& b)
  {
    const crypto::hash h = get_transaction_hash(b.miner_tx);

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
  uint64_t get_transaction_weight(const transaction &tx)
  {
    return t_serializable_object_to_blob(tx).size();
  }

  //---------------------------------------------------------------
  uint64_t get_tx_fee(const transaction& tx)
  {
    return tx.ringct.fee;
  }

  //---------------------------------------------------------------
  uint64_t get_block_height(const block& b)
  {
    LOG_ERROR_AND_RETURN_UNLESS
      (
       b.miner_tx.vin.size() == 1
       , 0
       , "wrong miner tx in block: " << get_block_hash(b) << ", b.miner_tx.vin.size() != 1"
       );

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
         << ", in transaction id=" << get_transaction_hash(tx)
         );

    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool check_outs_valid(const transaction& tx)
  {
    for(const tx_out& out: tx.vout)
    {
      LOG_ERROR_AND_RETURN_UNLESS
        (
         out.target.type() == typeid(txout_to_key)
         , false
         , "wrong variant type: "
         << out.target.type().name() << ", expected " << typeid(txout_to_key).name()
         << ", in transaction id=" << get_transaction_hash(tx)
         );

      if (tx.version == 1)
      {
        LOG_WITH_LEVEL_0_AND_RETURN_UNLESS(0 < out.amount, false, "zero amount output in transaction id=" << get_transaction_hash(tx));
      }

      if(!is_safe_point(boost::get<txout_to_key>(out.target).output_public_key))
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
  uint64_t get_tx_outputs_money_amount(const transaction& tx)
  {
    uint64_t outputs_amount = 0;
    for(const auto& o: tx.vout)
      outputs_amount += o.amount;
    return outputs_amount;
  }

  //---------------------------------------------------------------
  string_blob get_mining_blob_tail(const block& b)
  {
    string_blob blob;
    crypto::hash tree_root_hash = get_tx_tree_hash(b);
    blob.append(epee::string_tools::blob_to_string(tree_root_hash.data));
    blob.append(tools::get_varint_data(b.tx_hashes.size()+1));
    return blob;
  }
  //---------------------------------------------------------------
  string_blob get_mining_blob_head(const block& b)
  {
    string_blob blob = t_serializable_object_to_blob(static_cast<block_header>(b));
    return blob;
  }
  //---------------------------------------------------------------
  string_blob get_mining_blob(const block& b)
  {
    return get_mining_blob_head(b).append(get_mining_blob_tail(b));
  }

  //---------------------------------------------------------------
  crypto::hash get_block_hash(const block& b)
  {
    return get_object_hash(get_mining_blob(b));
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
  crypto::hash get_mining_hash(const block& b)
  {
    return crypto::sha3(epee::string_tools::string_to_blob(get_mining_blob(b)));
  }

  //---------------------------------------------------------------
  std::optional<transaction> expand_transaction(const transaction &tx_in)
  {
    transaction tx = tx_in;
    if (tx.version < 2) return tx;
    if (is_coinbase(tx)) return tx;

    rct::rctData &rv = tx.ringct;
    if (rv.type == rct::RCTTypeNull)
      return tx;

    if (rv.output_commits.size() != tx.vout.size())
    {
      LOG_PRINT_L1
        (
         "Failed to parse transaction from blob, bad output_commits size in tx "
         << get_transaction_hash(tx)
         );
      return {};
    }

    if (rv.p.bulletproofs.size() != 1)
    {
      LOG_PRINT_L1
        (
         "Failed to parse transaction from blob, bad bulletproofs size in tx "
         << get_transaction_hash(tx)
         );
      return {};
    }

    if (rv.p.bulletproofs[0].L.size() < 6)
    {
      LOG_PRINT_L1
        (
         "Failed to parse transaction from blob, bad bulletproofs L size in tx "
         << get_transaction_hash(tx)
         );
      return {};
    }

    const size_t max_outputs = 1 << (rv.p.bulletproofs[0].L.size() - 6);
    if (max_outputs < tx.vout.size())
    {
      LOG_PRINT_L1
        (
         "Failed to parse transaction from blob, bad bulletproofs max outputs in tx "
         << get_transaction_hash(tx)
         );
      return {};
    }

    const size_t n_amounts = tx.vout.size();
    LOG_ERROR_AND_RETURN_UNLESS
      (
       n_amounts == rv.output_commits.size()
       , {}
       , "Internal error filling out V"
       );

    std::transform
      (
       rv.output_commits.begin()
       , rv.output_commits.end()
       , std::back_inserter(rv.p.bulletproofs[0].commits)
       , [](const auto& x) {
         return x.commit ^ rct::s_inv_eight;
       }
       );

    return tx;
  }

  //---------------------------------------------------------------
  std::optional<transaction> maybe_tx_from_blob(const string_blob_view tx_blob)
  {
    const transaction dummyTx{};
    const auto maybeTx = maybe_from_blob(tx_blob, dummyTx);
    LOG_ERROR_AND_RETURN_UNLESS(maybeTx, {}, "Failed to parse transaction from blob");
    const auto maybeExpandedTx = expand_transaction(*maybeTx);
    LOG_ERROR_AND_RETURN_UNLESS(maybeExpandedTx, {}, "Failed to expand transaction data");
    return *maybeExpandedTx;
  }

  //---------------------------------------------------------------
  std::optional<transaction_prefix> maybe_tx_prefix_from_blob(const string_blob_view tx_blob)
  {
    transaction_prefix tx_prefix;
    std::stringstream ss;
    ss << tx_blob;
    binary_archive<false> ba(ss);
    const bool r = ::serialization::serialize_noeof(ba, tx_prefix);
    LOG_ERROR_AND_RETURN_UNLESS(r, {}, "Failed to parse transaction prefix from blob");
    return tx_prefix;
  }
  //---------------------------------------------------------------
  std::optional<std::pair<transaction, crypto::hash>>
  maybe_tx_and_hash_from_blob(const string_blob_view tx_blob)
  {
    const auto maybeTx = maybe_tx_from_blob(tx_blob);
    if (maybeTx) {
      return {{*maybeTx, get_transaction_hash(*maybeTx)}};
    }
    else {
      return {};
    }
  }

  //---------------------------------------------------------------
  std::optional<block> maybe_block_from_blob(const string_blob_view b_blob)
  {
    const block dummyBlock{};
    return maybe_from_blob(b_blob, dummyBlock);
  }

  //---------------------------------------------------------------
  std::optional<std::pair<block, crypto::hash>>
  maybe_block_and_hash_from_blob(const string_blob_view b_blob)
  {
    const auto maybeBlock = maybe_block_from_blob(b_blob);
    if (maybeBlock) {
      const auto& b = *maybeBlock;
      const auto block_hash = get_block_hash(b);
      return {{b, block_hash}};
    } else {
      return {};
    }
  }


  //---------------------------------------------------------------
  string_blob block_to_blob(const block& b)
  {
    return t_serializable_object_to_blob(b);
  }
  //---------------------------------------------------------------
  std::optional<string_blob> maybe_block_to_blob(const block& b)
  {
    return maybe_to_blob(b);
  }
  //---------------------------------------------------------------
  string_blob tx_to_blob(const transaction& tx)
  {
    return t_serializable_object_to_blob(tx);
  }

  //---------------------------------------------------------------
  std::optional<string_blob> maybe_tx_to_blob(const transaction& tx)
  {
    return maybe_to_blob(tx);
  }

  //---------------------------------------------------------------
  uint64_t get_inputs_money_amount(const transaction& tx)
  {
    return std::transform_reduce
      (
       tx.vin.begin()
       , tx.vin.end()
       , 0ull
       , std::plus()
       , [](const auto& x) -> uint64_t {
         CHECKED_GET_SPECIFIC_VARIANT(x, const txin_to_key, tokey_in, 0);
         return tokey_in.amount;
       }
       );
  }
}

