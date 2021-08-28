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

#include "cryptonote_tx_utils.h"


#include "tools/common/apply_permutation.h"
#include "tools/epee/include/string_tools.h"

#include "math/crypto/controller/random.hpp"

#include "math/ringct/pseudo_functional/rctSigs.hpp"
#include "math/ringct/controller/rctSigGen.hpp"





namespace cryptonote
{
  //---------------------------------------------------------------
  void classify_addresses
  (
   const std::vector<tx_destination_entry> &destinations
   , const std::optional<cryptonote::account_public_address>& change_addr
   , size_t &num_stdaddresses
   , size_t &num_subaddresses
   , account_public_address &single_dest_subaddress
   )
  {
    num_stdaddresses = 0;
    num_subaddresses = 0;
    std::unordered_set<cryptonote::account_public_address> unique_dst_addresses;
    for(const tx_destination_entry& dst_entr: destinations)
    {
      if (change_addr && dst_entr.addr == change_addr)
        continue;
      if (unique_dst_addresses.count(dst_entr.addr) == 0)
      {
        unique_dst_addresses.insert(dst_entr.addr);
        if (dst_entr.is_subaddress)
        {
          ++num_subaddresses;
          single_dest_subaddress = dst_entr.addr;
        }
        else
        {
          ++num_stdaddresses;
        }
      }
    }
    LOG_PRINT_L2("destinations include " << num_stdaddresses << " standard addresses and " << num_subaddresses << " subaddresses");
  }
  //---------------------------------------------------------------
  bool construct_miner_tx
    (
      size_t height
      , size_t current_block_weight
      , uint64_t fee
      , const account_public_address &miner_address
      , transaction& tx
      , const blobdata& extra_nonce
      , size_t max_outs
      )
  {
    tx.vin.clear();
    tx.vout.clear();
    tx.extra.clear();

    keypair txkey = keypair::generate(hw::get_device("default"));
    add_tx_pub_key_to_extra(tx, txkey.pub);
    if (!sort_tx_extra(tx.extra, tx.extra))
      return false;

    txin_gen in;
    in.height = height;

    if(!check_block_weight(static_cast<uint64_t>(height), current_block_weight))
    {
      LOG_PRINT_L0("Block is too big");
      return false;
    }
    uint64_t block_reward = get_block_reward();

#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
    LOG_PRINT_L1("Creating block template: reward " << block_reward <<
      ", fee " << fee);
#endif
    block_reward += fee;

    std::optional<crypto::key_derivation> derivation = crypto::derive_key_derivation(miner_address.m_view_public_key, txkey.sec);
    LOG_ERROR_AND_RETURN_UNLESS(derivation, false, "while creating outs: failed to derive_key_derivation(" << miner_address.m_view_public_key << ", " << txkey.sec << ")");

    const std::optional<crypto::public_key> out_eph_public_key =
      crypto::derive_tx_public_key(*derivation, 0, miner_address.m_spend_public_key);
    LOG_ERROR_AND_RETURN_UNLESS
      (
       out_eph_public_key
       , false
       , "while creating outs: failed to derive_tx_public_key("
       << *derivation << ", " << 0 << ", "
       << miner_address.m_spend_public_key << ")"
       );

    txout_to_key tk;
    tk.key = *out_eph_public_key;

    tx_out out;
    out.amount = block_reward;
    out.target = tk;
    tx.vout.push_back(out);

    tx.version = 2;

    //lock
    tx.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
    tx.vin.push_back(in);

    tx.invalidate_hashes();

    //LOG_PRINT("MINER_TX generated ok, block_reward=" << print_money(block_reward) << "("  << print_money(block_reward - fee) << "+" << print_money(fee)
    //  << "), current_block_size=" << current_block_size << ", already_generated_coins=" << already_generated_coins << ", tx_id=" << get_transaction_hash(tx), LOG_LEVEL_2);
    return true;
  }
  //---------------------------------------------------------------
  bool construct_tx_with_tx_key
  (
   const account_keys& sender_account_keys
   , const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses
   , std::vector<tx_source_entry>& sources
   , std::vector<tx_destination_entry>& destinations
   , const std::optional<cryptonote::account_public_address>& change_addr
   , const std::vector<uint8_t> &extra
   , transaction& tx
   , uint64_t unlock_time
   , const crypto::secret_key &tx_key
   , const std::vector<crypto::secret_key> &additional_tx_keys
   , bool rct
   , bool shuffle_outs
   )
  {
    hw::device &hwdev = sender_account_keys.get_device();

    if (sources.empty())
    {
      LOG_ERROR("Empty sources");
      return false;
    }

    rct::rct_scalarV amount_keys;
    tx.set_null();

    tx.version = rct ? 2 : 1;
    tx.unlock_time = unlock_time;

    tx.extra = extra;
    crypto::public_key txkey_pub;

    struct input_generation_context_data
    {
      keypair in_ephemeral;
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
        return false;
      }
      summary_inputs_money += src_entr.amount;

      //key_derivation recv_derivation;
      in_contexts.push_back(input_generation_context_data());
      keypair& in_ephemeral = in_contexts.back().in_ephemeral;
      crypto::key_image img;
      const auto& out_key = reinterpret_cast<const crypto::public_key&>(src_entr.outputs[src_entr.real_output].second.dest);
      if(!derive_key_image_helper(sender_account_keys, subaddresses, out_key, src_entr.real_out_tx_key, src_entr.real_out_additional_tx_keys, src_entr.real_output_in_tx_index, in_ephemeral,img, hwdev))
      {
        LOG_ERROR("Key image generation failed!");
        return false;
      }

      //check that derivated key is equal with real output key (if non multisig)
      if(!(in_ephemeral.pub == src_entr.outputs[src_entr.real_output].second.dest) )
      {
        LOG_ERROR("derived public key mismatch with output public key at index " << idx << ", real out " << src_entr.real_output << "! "<< std::endl << "derived_key:"
          << epee::string_tools::pod_to_hex(in_ephemeral.pub) << std::endl << "real output_public_key:"
          << epee::string_tools::pod_to_hex(src_entr.outputs[src_entr.real_output].second.dest) );
        LOG_ERROR("amount " << src_entr.amount << ", rct " << src_entr.rct);
        LOG_ERROR("tx pubkey " << src_entr.real_out_tx_key << ", real_output_in_tx_index " << src_entr.real_output_in_tx_index);
        return false;
      }

      //put key image into tx input
      txin_to_key input_to_key;
      input_to_key.amount = src_entr.amount;
      input_to_key.k_image = img;

      //fill outputs array and use relative offsets
      for(const tx_source_entry::output_entry& out_entry: src_entr.outputs)
        input_to_key.key_offsets.push_back(out_entry.first);

      input_to_key.key_offsets = absolute_output_offsets_to_relative(input_to_key.key_offsets);
      tx.vin.push_back(input_to_key);
    }

    if (shuffle_outs)
    {
      std::shuffle(destinations.begin(), destinations.end(), crypto::random_device{});
    }

    // sort ins by their key image
    std::vector<size_t> ins_order(sources.size());
    for (size_t n = 0; n < sources.size(); ++n)
      ins_order[n] = n;
    std::sort(ins_order.begin(), ins_order.end(), [&](const size_t i0, const size_t i1) {
      const txin_to_key &tk0 = boost::get<txin_to_key>(tx.vin[i0]);
      const txin_to_key &tk1 = boost::get<txin_to_key>(tx.vin[i1]);
      return memcmp(&tk0.k_image, &tk1.k_image, sizeof(tk0.k_image)) > 0;
    });
    tools::apply_permutation(ins_order, [&] (size_t i0, size_t i1) {
      std::swap(tx.vin[i0], tx.vin[i1]);
      std::swap(in_contexts[i0], in_contexts[i1]);
      std::swap(sources[i0], sources[i1]);
    });

    // figure out if we need to make additional tx pubkeys
    size_t num_stdaddresses = 0;
    size_t num_subaddresses = 0;
    account_public_address single_dest_subaddress;
    classify_addresses(destinations, change_addr, num_stdaddresses, num_subaddresses, single_dest_subaddress);

    // if this is a single-destination transfer to a subaddress, we set the tx pubkey to R=s*D
    if (num_stdaddresses == 0 && num_subaddresses == 1)
    {
      txkey_pub = rct::rct_p2pk
        (hwdev.multP(rct::pk2rct_p(single_dest_subaddress.m_spend_public_key), rct::sk2rct_s(tx_key)));
    }
    else
    {
      txkey_pub = rct::rct_p2pk(hwdev.multG(rct::sk2rct_s(tx_key)));
    }
    remove_field_from_tx_extra(tx.extra, typeid(tx_extra_pub_key));
    add_tx_pub_key_to_extra(tx, txkey_pub);

    std::vector<crypto::public_key> additional_tx_public_keys;

    // we don't need to include additional tx keys if:
    //   - all the destinations are standard addresses
    //   - there's only one destination which is a subaddress
    bool need_additional_txkeys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);
    if (need_additional_txkeys)
      LOG_ERROR_AND_RETURN_UNLESS(destinations.size() == additional_tx_keys.size(), false, "Wrong amount of additional tx keys");

    uint64_t summary_outs_money = 0;
    //fill outputs
    size_t output_index = 0;
    for(const tx_destination_entry& dst_entr: destinations)
    {
      LOG_ERROR_AND_RETURN_UNLESS(dst_entr.amount > 0 || tx.version > 1, false, "Destination with wrong amount: " << dst_entr.amount);
      crypto::public_key out_eph_public_key;

      hwdev.generate_output_ephemeral_keys(tx.version,sender_account_keys, txkey_pub, tx_key,
                                           dst_entr, change_addr, output_index,
                                           need_additional_txkeys, additional_tx_keys,
                                           additional_tx_public_keys, amount_keys, out_eph_public_key);

      tx_out out;
      out.amount = dst_entr.amount;
      txout_to_key tk;
      tk.key = out_eph_public_key;
      out.target = tk;
      tx.vout.push_back(out);
      output_index++;
      summary_outs_money += dst_entr.amount;
    }
    LOG_ERROR_AND_RETURN_UNLESS(additional_tx_public_keys.size() == additional_tx_keys.size(), false, "Internal error creating additional public keys");

    remove_field_from_tx_extra(tx.extra, typeid(tx_extra_additional_pub_keys));

    LOG_PRINT_L2("tx pubkey: " << txkey_pub);
    if (need_additional_txkeys)
    {
      LOG_PRINT_L2("additional tx pubkeys: ");
      for (size_t i = 0; i < additional_tx_public_keys.size(); ++i)
        LOG_PRINT_L2(additional_tx_public_keys[i]);
      add_additional_tx_pub_keys_to_extra(tx.extra, additional_tx_public_keys);
    }

    if (!sort_tx_extra(tx.extra, tx.extra))
      return false;

    //check money
    if(summary_outs_money > summary_inputs_money )
    {
      LOG_ERROR("Transaction inputs money ("<< summary_inputs_money << ") less than outputs money (" << summary_outs_money << ")");
      return false;
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
      bool use_simple_rct = true;

      uint64_t amount_in = 0, amount_out = 0;
      rct::ct_secret_keyV inSk;
      inSk.reserve(sources.size());
      // mixRing indexing is done the other way round for simple
      rct::ct_public_keyM mixRing(sources.size());
      rct::rct_pointV destinations;
      std::vector<uint64_t> inamounts, outamounts;
      std::vector<size_t> index;
      for (size_t i = 0; i < sources.size(); ++i)
      {
        rct::ct_secret_key ct_public_key;
        amount_in += sources[i].amount;
        inamounts.push_back(sources[i].amount);
        index.push_back(sources[i].real_output);
        // inSk: (secret key, mask)
        ct_public_key.addr = rct::sk2rct_s(in_contexts[i].in_ephemeral.sec);
        ct_public_key.blinding_factor = sources[i].mask;
        inSk.push_back(ct_public_key);
        // inPk: (public key, commitment)
        // will be done when filling in mixRing
      }
      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
        destinations.push_back(rct::pk2rct_p(boost::get<txout_to_key>(tx.vout[i].target).key));
        outamounts.push_back(tx.vout[i].amount);
        amount_out += tx.vout[i].amount;
      }

      if (use_simple_rct)
      {
        // mixRing indexing is done the other way round for simple
        for (size_t i = 0; i < sources.size(); ++i)
        {
          mixRing[i].resize(sources[i].outputs.size());
          for (size_t n = 0; n < sources[i].outputs.size(); ++n)
          {
            mixRing[i][n] = sources[i].outputs[n].second;
          }
        }
      }

      // fee
      if (!use_simple_rct && amount_in > amount_out)
        outamounts.push_back(amount_in - amount_out);

      // zero out all amounts to mask rct outputs, real amounts are now encrypted
      for (size_t i = 0; i < tx.vin.size(); ++i)
      {
        if (sources[i].rct)
          boost::get<txin_to_key>(tx.vin[i]).amount = 0;
      }
      for (size_t i = 0; i < tx.vout.size(); ++i)
        tx.vout[i].amount = 0;

      crypto::hash tx_prefix_hash;
      get_transaction_prefix_hash(tx, tx_prefix_hash, hwdev);
      rct::ct_secret_keyV outSk;
      std::tie(tx.rct_signatures, outSk) = rct::genRctSimple
        (tx_prefix_hash, inSk, destinations, inamounts, outamounts, amount_in - amount_out, mixRing, amount_keys, index);

      LOG_ERROR_AND_RETURN_UNLESS(tx.vout.size() == outSk.size(), false, "outSk size does not match vout");

      LOG_CATEGORY_INFO("construct_tx", "transaction_created: " << get_transaction_hash(tx) << std::endl << obj_to_json_str(tx) << std::endl);
    }

    tx.invalidate_hashes();

    return true;
  }
  //---------------------------------------------------------------
  bool construct_tx_and_get_tx_key
  (
   const account_keys& sender_account_keys
   , const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses
   , std::vector<tx_source_entry>& sources
   , std::vector<tx_destination_entry>& destinations
   , const std::optional<cryptonote::account_public_address>& change_addr
   , const std::vector<uint8_t> &extra
   , transaction& tx
   , uint64_t unlock_time
   , crypto::secret_key &tx_key
   , std::vector<crypto::secret_key> &additional_tx_keys
   , bool rct
   )
  {
    hw::device &hwdev = sender_account_keys.get_device();
    hwdev.open_tx(tx_key);
    try {
      // figure out if we need to make additional tx pubkeys
      size_t num_stdaddresses = 0;
      size_t num_subaddresses = 0;
      account_public_address single_dest_subaddress;
      classify_addresses(destinations, change_addr, num_stdaddresses, num_subaddresses, single_dest_subaddress);
      bool need_additional_txkeys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);
      if (need_additional_txkeys)
      {
        additional_tx_keys.clear();
        additional_tx_keys.resize(5);
        std::generate(additional_tx_keys.begin(), additional_tx_keys.end(),
                      [sender_account_keys]()  {
                        return keypair::generate(sender_account_keys.get_device()).sec;
                      });
      }

      bool r = construct_tx_with_tx_key(sender_account_keys, subaddresses, sources, destinations, change_addr, extra, tx, unlock_time, tx_key, additional_tx_keys, rct);
      hwdev.close_tx();
      return r;
    } catch(...) {
      hwdev.close_tx();
      throw;
    }
  }
  //---------------------------------------------------------------
  bool generate_genesis_block(
      block& bl
    , std::string_view const & genesis_tx
    , uint64_t nonce
    )
  {
    //genesis block
    bl = {};

    blobdata tx_bl;
    bool r = epee::string_tools::parse_hexstr_to_binbuff(genesis_tx, tx_bl);
    LOG_ERROR_AND_RETURN_UNLESS(r, false, "failed to parse coinbase tx from hard coded blob");
    r = parse_and_validate_tx_from_blob(tx_bl, bl.miner_tx);
    LOG_ERROR_AND_RETURN_UNLESS(r, false, "failed to parse coinbase tx from hard coded blob");
    bl.major_version = config::lol::constant_hf_version;
    bl.minor_version = config::lol::constant_hf_version;
    bl.timestamp = 0;
    bl.nonce = nonce;
    bl.invalidate_hashes();
    return true;
  }
  //---------------------------------------------------------------
  bool get_block_longhash(const block& b, crypto::hash& res)
  {
    blobdata bd = get_block_hashing_blob(b);
    res = crypto::sha3(epee::string_tools::string_to_blob(bd));
    return true;
  }

  crypto::hash get_block_longhash(const block& b)
  {
    crypto::hash p = crypto::null_hash;
    get_block_longhash(b, p);
    return p;
  }
}
