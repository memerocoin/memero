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

#include "tx_utils.hpp"

#include "tools/epee/include/string_tools.h"
#include "tools/common/apply_permutation.h"

#include "math/crypto/controller/random.hpp"

#include "math/ringct/pseudo_functional/ringCT.hpp"
#include "math/ringct/controller/ringCT_Gen.hpp"

#include "cryptonote/functional/helper.hpp"
#include "math/blockchain/functional/subaddress.hpp"
#include "cryptonote/basic/functional/tx_extra.hpp"
#include "cryptonote/basic/functional/format_utils.hpp"

#include "consensus/consensus.hpp"



namespace cryptonote
{
  std::optional<
    std::tuple<
    std::vector<crypto::public_key>
    , rct::rct_scalarV
    , crypto::public_key
    >>

    generate_output_key_pairs

  (
   const size_t tx_version
   , const cryptonote::account_keys sender_account_keys
   , const cryptonote::tx_destination_entry dst_entr
   , const size_t output_index
   , const std::span<const crypto::secret_key> output_secret_keys
   , const std::vector<crypto::public_key> &output_public_keys_in
   , const rct::rct_scalarV &output_shared_secrets_hashed_by_index_in
   )
  {
    const keypair txkey =
      keypair
      {
        output_secret_keys[output_index]
        , {
          dst_entr.is_subaddress
          // This change of base is only to be used in later schnorr signature, as payment proof
          // since the base point has to be part of the proof.
          // It's otherwise useless.
          ? dst_entr.addr.m_spend_public_key ^ output_secret_keys[output_index]
          : to_pk(output_secret_keys[output_index])
        }
      };

    const auto tx_output_shared_secret =
      crypto::derive_tx_output_ecdh_shared_secret(dst_entr.addr.m_view_public_key, txkey.sec);

    const rct::rct_scalar tx_output_shared_secret_indexed_hash =
      crypto::hash_tx_output_shared_secret_to_scalar(tx_output_shared_secret, output_index);

    const auto eph_pk = crypto::compute_output_public_key_from_subaddress_spend_pk
      (tx_output_shared_secret, output_index, dst_entr.addr.m_spend_public_key);

    LOG_ERROR_AND_RETURN_UNLESS
      (
       eph_pk
       , {}
       , "at creation outs: failed to compute_output_public_key_from_subaddress_spend_pk("
       << tx_output_shared_secret << ", " << output_index << ", "<< dst_entr.addr.m_spend_public_key << ")"
       );

    // carry
    std::vector<crypto::public_key> output_public_keys = output_public_keys_in;
    output_public_keys.push_back(txkey.pub);

    rct::rct_scalarV output_shared_secrets_hashed_by_index = output_shared_secrets_hashed_by_index_in;
    output_shared_secrets_hashed_by_index.push_back(tx_output_shared_secret_indexed_hash);

    return {{
        output_public_keys
        , output_shared_secrets_hashed_by_index
        , *eph_pk
      }};
  }

  //---------------------------------------------------------------
  std::optional
  <
    std::tuple
    <
      transaction
      , std::vector<size_t>
      >
    > construct_tx_with_tx_key
  (
   const account_keys sender_account_keys
   , const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses
   , const std::vector<tx_source_entry> sources_in
   , const std::span<const tx_destination_entry> destinations
   , const std::vector<uint8_t> extra
   , const uint64_t unlock_height
   , const std::span<const crypto::secret_key> output_secret_keys
   )
  {
    transaction tx;
    std::vector<tx_source_entry> sources = sources_in;

    if (sources.empty())
    {
      LOG_ERROR("Empty sources");
      return {};
    }


    rct::rct_scalarV output_shared_secrets_hashed_by_index;

    tx.version = 2;
    tx.unlock_height = unlock_height;

    tx.extra = extra;

    struct input_generation_context_data
    {
      keypair output_key_pair;
    };
    std::vector<input_generation_context_data> in_contexts;

    uint64_t summary_inputs_money = 0;
    //fill inputs
    int idx = -1;
    for(const tx_source_entry& src_entr:  sources)
    {
      ++idx;
      if(src_entr.real_output >= src_entr.outputs.size())
      {
        LOG_ERROR("real_output index (" << src_entr.real_output << ")bigger than output_keys.size()=" << src_entr.outputs.size());
        return {};
      }
      summary_inputs_money += src_entr.amount;

      //tx_output_ecdh_shared_secret recv_tx_output_shared_secret;
      in_contexts.push_back(input_generation_context_data());
      const crypto::public_key out_key = crypto::p2pk(src_entr.outputs[src_entr.real_output].second.output_public_key);
      const auto r = derive_with_internal_checking_output_key_pair_and_key_image
        (
         sender_account_keys
         , subaddresses
         , out_key
         , crypto::maybeNotNull(src_entr.real_out_tx_key)
         , src_entr.real_out_output_secret_keys
         , src_entr.real_output_in_tx_index
         )
        ;

      if (!r)
      {
        LOG_ERROR("Key image generation failed!");
        return {};
      }

      keypair& output_key_pair = in_contexts.back().output_key_pair;
      crypto::key_image img;

      std::tie(output_key_pair, img) = *r;

      //check that derivated key is equal with real output key (if non multisig)
      if(!(output_key_pair.pub == src_entr.outputs[src_entr.real_output].second.output_public_key) )
      {
        LOG_ERROR("derived public key mismatch with output public key at index " << idx << ", real out " << src_entr.real_output << "! "<< std::endl << "derived_key:"
          << epee::string_tools::pod_to_hex(output_key_pair.pub) << std::endl << "real output_public_key:"
          << epee::string_tools::pod_to_hex(src_entr.outputs[src_entr.real_output].second.output_public_key) );
        LOG_ERROR("amount " << src_entr.amount << ", rct " << src_entr.rct);
        LOG_ERROR("tx pubkey " << src_entr.real_out_tx_key);
        LOG_ERROR(", real_output_in_tx_index " << src_entr.real_output_in_tx_index);
        return {};
      }

      //put key image into tx input
      txin_to_key input_to_key;
      input_to_key.amount = src_entr.amount;
      input_to_key.output_key_image = img;

      //fill outputs array and use relative offsets
      for(const tx_source_entry::output_entry& out_entry: src_entr.outputs)
        input_to_key.output_relative_offsets.push_back(out_entry.first);

      input_to_key.output_relative_offsets = absolute_output_offsets_to_relative(input_to_key.output_relative_offsets);
      tx.vin.push_back(input_to_key);
    }

    // if (shuffle_outs)
    // {
    //   std::shuffle(destinations.begin(), destinations.end(), crypto::random_device{});
    // }

    // sort ins by their key image
    std::vector<crypto::key_image> output_public_key_images;
    std::transform
      (
       tx.vin.begin()
       , tx.vin.end()
       , std::back_inserter(output_public_key_images)
       , [](const auto& x) {
         const txin_to_key &tk = boost::get<txin_to_key>(x);
         return tk.output_key_image;
         }
       );

    const std::vector<size_t> permutation = tools::get_sorted_permutation(output_public_key_images);
    tx.vin = tools::apply_permutation(permutation, tx.vin);
    in_contexts = tools::apply_permutation(permutation, in_contexts);
    sources = tools::apply_permutation(permutation, sources);

    // if this is a single-destination transfer to a subaddress, we set the tx pubkey to R=s*D
    const auto maybe_new_extra = remove_field_from_tx_extra(tx.extra, typeid(tx_extra_tx_public_key));
    if (maybe_new_extra) {
      tx.extra = *maybe_new_extra;
    }

    std::vector<crypto::public_key> output_public_keys;

    LOG_ERROR_AND_RETURN_UNLESS(destinations.size() == output_secret_keys.size(), {}, "Wrong amount of tx output public keys");

    uint64_t summary_outs_money = 0;
    //fill outputs
    size_t output_index = 0;
    for(const tx_destination_entry& dst_entr: destinations)
    {
      LOG_ERROR_AND_RETURN_UNLESS(dst_entr.amount > 0 || tx.version > 1, {}, "Destination with wrong amount: " << dst_entr.amount);

      const auto r = generate_output_key_pairs
        (
         tx.version,sender_account_keys
         , dst_entr
         , output_index
         , output_secret_keys
         , output_public_keys
         , output_shared_secrets_hashed_by_index
         );

      if (!r) return {};

      crypto::public_key out_eph_public_key;
      std::tie
        (
         output_public_keys
         , output_shared_secrets_hashed_by_index
         , out_eph_public_key
         ) = *r;

      const txout_to_key txout_key_type{out_eph_public_key};
      const tx_out out{dst_entr.amount, txout_key_type};

      tx.vout.push_back(out);
      output_index++;
      summary_outs_money += dst_entr.amount;
    }
    LOG_ERROR_AND_RETURN_UNLESS(output_public_keys.size() == output_secret_keys.size(), {}, "Internal error creating tx output public keys");

    const auto maybe_new_extra_2 = remove_field_from_tx_extra(tx.extra, typeid(tx_extra_tx_output_public_keys));
    if (maybe_new_extra) {
      tx.extra = *maybe_new_extra_2;
    }

    LOG_PRINT_L2("tx output pubkeys: ");
    for (size_t i = 0; i < output_public_keys.size(); ++i)
      LOG_PRINT_L2(output_public_keys[i]);

    tx.extra = add_tx_output_keys_to_extra(tx.extra, output_public_keys);

    //check money
    if(summary_outs_money > summary_inputs_money )
    {
      LOG_ERROR("Transaction inputs money ("<< summary_inputs_money << ") less than outputs money (" << summary_outs_money << ")");
      return {};
    }

    // check for watch only wallet
    bool zero_secret_key = true;
    if (zero_secret_key)
    {
      LOG_DEBUG("Null secret key, skipping signatures");
    }

    {

      // the non-simple version is slightly smaller, but assumes all real inputs
      // are on the same index, so can only be used if there just one ring.

      uint64_t amount_in = 0, amount_out = 0;
      // rct::ct_secret_keyV inSk;
      // inSk.reserve(sources.size());
      std::vector<rct::rctInputData> inputs;
      std::vector<rct::rctOutputData> outputs;

      // decoys indexing is done the other way round for simple
      rct::output_public_dataM decoys(sources.size());
      for (size_t i = 0; i < sources.size(); ++i)
      {
        amount_in += sources[i].amount;
        // inSk: (secret key, mask)

        decoys[i].resize(sources[i].outputs.size());
        for (size_t n = 0; n < sources[i].outputs.size(); ++n)
        {
          decoys[i][n] = sources[i].outputs[n].second;
        }

        const rct::rctInputData input =
          {
            sources[i].amount
            , in_contexts[i].output_key_pair.sec
            , sources[i].mask
            , sources[i].real_output
            , decoys[i]
          };

        inputs.push_back(input);

        // inPk: (public key, commitment)
        // will be done when filling in decoys
      }

      LOG_ERROR_AND_RETURN_UNLESS
        (
         tx.vout.size() == output_shared_secrets_hashed_by_index.size()
         , {}
         , "wrong number of outptu secrets"
         );

      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
        outputs.push_back({tx.vout[i].amount, output_shared_secrets_hashed_by_index[i]});
        amount_out += tx.vout[i].amount;
      }

      // zero out all amounts to mask rct outputs, real amounts are now encrypted
      for (size_t i = 0; i < tx.vin.size(); ++i)
      {
        if (sources[i].rct)
          boost::get<txin_to_key>(tx.vin[i]).amount = 0;
      }
      for (size_t i = 0; i < tx.vout.size(); ++i)
        tx.vout[i].amount = 0;

      const crypto::hash tx_prefix_hash = get_transaction_prefix_hash(tx);

      tx.ringct = rct::toRctData
        (
         rct::generate_ringct
         (
          tx_prefix_hash
          , inputs
          , outputs
          , amount_in - amount_out
          )
         );

      // LOG_ERROR_AND_RETURN_UNLESS
      //   (
      //    tx.vout.size() == tx.ringct.size()
      //    , {}
      //    , "outSk size does not match vout"
      //    );
      const auto tx_hash = get_transaction_hash(tx);
      LOG_CATEGORY_INFO("construct_tx", "transaction_created: " << tx_hash << std::endl << obj_to_json_str(tx) << std::endl);
    }

    return {{tx, permutation}};
  }
  //---------------------------------------------------------------
  std::optional<block> generate_genesis_block
  (
   const std::string_view genesis_tx
   , const uint64_t nonce
   )
  {
    //genesis block
    block bl = {};

    string_blob tx_bl;
    bool r = epee::string_tools::parse_hexstr_to_binbuff(genesis_tx, tx_bl);
    LOG_ERROR_AND_RETURN_UNLESS(r, {}, "failed to parse coinbase tx from hard coded blob");

    const auto maybeTx = maybe_tx_from_blob(tx_bl);
    LOG_ERROR_AND_RETURN_UNLESS(maybeTx, {}, "failed to parse coinbase tx from hard coded blob");
    bl.miner_tx = *maybeTx;

    bl.major_version = config::lol::constant_hf_version;
    bl.minor_version = config::lol::constant_hf_version;
    bl.timestamp = 0;
    bl.nonce = nonce;

    return bl;
  }

  //---------------------------------------------------------------
  std::optional<transaction> construct_miner_tx
  (
   const size_t height
   , const size_t current_block_weight
   , const uint64_t fee
   , const spend_view_public_keys miner_address
   )
  {
    transaction tx;

    tx.vin.clear();
    tx.vout.clear();
    tx.extra.clear();

    keypair txkey = keypair::generate();
    tx = add_tx_pub_key_to_extra(tx, txkey.pub);

    txin_gen in;
    in.height = height;

    if(!consensus::is_block_size_valid(static_cast<uint64_t>(height), current_block_weight))
    {
      LOG_PRINT_L0("Block is too big");
      return {};
    }
    uint64_t block_reward = consensus::get_block_reward();

    block_reward += fee;

    const auto tx_output_shared_secret =
      crypto::derive_tx_output_ecdh_shared_secret(miner_address.m_view_public_key, txkey.sec);

    const std::optional<crypto::public_key> out_eph_public_key =
      crypto::compute_output_public_key_from_subaddress_spend_pk(tx_output_shared_secret, 0, miner_address.m_spend_public_key);

    LOG_ERROR_AND_RETURN_UNLESS
      (
       out_eph_public_key
       , {}
       , "while creating outs: failed to compute_output_public_key_from_subaddress_spend_pk("
       << tx_output_shared_secret << ", " << 0 << ", "
       << miner_address.m_spend_public_key << ")"
       );

    txout_to_key tk;
    tk.output_public_key = *out_eph_public_key;

    tx_out out;
    out.amount = block_reward;
    out.target = tk;
    tx.vout.push_back(out);

    tx.version = 2;

    //lock
    tx.unlock_height = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
    tx.vin.push_back(in);

    //LOG_PRINT("MINER_TX generated ok, block_reward=" << print_money(block_reward) << "("  << print_money(block_reward - fee) << "+" << print_money(fee)
    //  << "), current_block_size=" << current_block_size << ", already_generated_coins=" << already_generated_coins << ", tx_id=" << get_transaction_hash(tx), LOG_LEVEL_2);
    return tx;
  }

}
