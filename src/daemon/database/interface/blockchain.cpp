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

#include "../instance/lmdb/lmdb.hpp"

#include "cryptonote/basic/functional/format_utils.hpp"

#include "math/ringct/functional/rctOps.hpp"

#include "tools/epee/include/string_tools.h"

#include <boost/range/adaptor/reversed.hpp>




using epee::string_tools::pod_to_hex;

namespace cryptonote
{

bool matches_category(relay_method method, relay_category category) noexcept
{
  switch (category)
  {
    default:
      return false;
    case relay_category::all:
      return true;
    case relay_category::relayable:
      if (method == relay_method::none)
        return false;
      return true;
    case relay_category::broadcasted:
    case relay_category::legacy:
      break;
  }
  // check for "broadcasted" or "legacy" methods:
  switch (method)
  {
    default:
    case relay_method::local:
      return false;
    case relay_method::block:
    case relay_method::fluff:
      return true;
    case relay_method::none:
      break;
  }
  return category == relay_category::legacy;
}

void txpool_tx_meta_t::set_relay_method(relay_method method) noexcept
{
  tx_from_block = 0;
  do_not_relay = 0;
  is_local = 0;

  switch (method)
  {
    case relay_method::none:
      do_not_relay = 1;
      break;
    case relay_method::local:
      is_local = 1;
      break;
    default:
    case relay_method::fluff:
      break;
    case relay_method::block:
      tx_from_block = 1;
      break;
  }
}

relay_method txpool_tx_meta_t::get_relay_method() const noexcept
{
  if (tx_from_block)
    return relay_method::block;
  if (do_not_relay)
    return relay_method::none;
  if (is_local)
    return relay_method::local;
  return relay_method::fluff;
}

void BlockchainDB::init_options(boost::program_options::options_description& desc)
{
}

void BlockchainDB::add_transaction(const crypto::hash& blk_hash, const std::pair<transaction, string_blob_view>& txp, const crypto::hash* tx_hash_ptr)
{
  const transaction &tx = txp.first;

  bool miner_tx = false;
  crypto::hash tx_hash;
  if (!tx_hash_ptr)
  {
    // should only need to compute hash for miner transactions
    tx_hash = get_transaction_hash(tx);
    LOG_PRINT_L3("null tx_hash_ptr - needed to compute: " + tx_hash.to_str());
  }
  else
  {
    tx_hash = *tx_hash_ptr;
  }
  for (const txin_v& tx_input : tx.vin)
  {
    if (tx_input.type() == typeid(txin_from_key))
    {
      add_spent_key(boost::get<txin_from_key>(tx_input).output_key_image);
    }
    else if (tx_input.type() == typeid(txin_gen))
    {
      /* nothing to do here */
      miner_tx = true;
    }
    else
    {
      LOG_PRINT_L1("Unsupported input type, removing key images and aborting transaction addition");
      for (const txin_v& tx_input : tx.vin)
      {
        if (tx_input.type() == typeid(txin_from_key))
        {
          remove_spent_key(boost::get<txin_from_key>(tx_input).output_key_image);
        }
      }
      return;
    }
  }

  uint64_t tx_id = add_transaction_data(blk_hash, txp, tx_hash);

  std::vector<uint64_t> amount_output_indices(tx.vout.size());

  // iterate tx.vout using indices instead of C++11 foreach syntax because
  // we need the index
  for (uint64_t i = 0; i < tx.vout.size(); ++i)
  {
    // miner v2 txes have their coinbase output in one single out to save space,
    // and we store them as rct outputs with an identity mask
    if (miner_tx && tx.version == 2)
    {
      cryptonote::tx_out vout = tx.vout[i];
      crypto::ec_point commitment = rct::dummyCommit(vout.amount);
      vout.amount = 0;
      amount_output_indices[i] =
        add_output(tx_hash, vout, i, tx.unlock_height, commitment);
    }
    else if (miner_tx && tx.version == 1)
    {

      amount_output_indices[i] =
        add_output(tx_hash, tx.vout[i], i, tx.unlock_height, {});
    }
    else
    {
      amount_output_indices[i] =
        add_output(tx_hash, tx.vout[i], i, tx.unlock_height, tx.ringct.output_commits[i].commit);
    }
  }
  add_tx_amount_output_indices(tx_id, amount_output_indices);
}

uint64_t BlockchainDB::add_block( const std::pair<block, string_blob>& blck
                                , size_t block_weight
                                , uint64_t long_term_block_weight
                                , const diff_t& cumulative_difficulty
                                , const uint64_t& coins_generated
                                , const std::vector<std::pair<transaction, string_blob>>& txs
                                )
{
  const block &blk = blck.first;

  // sanity
  if (blk.tx_hashes.size() != txs.size())
    throw std::runtime_error("Inconsistent tx/hashes sizes");

  crypto::hash blk_hash = get_block_hash(blk);

  uint64_t prev_height = height();

  // call out to add the transactions

  uint64_t num_rct_outs = 0;
  string_blob miner_bd = tx_to_blob(blk.miner_tx);
  add_transaction(blk_hash, std::make_pair(blk.miner_tx, string_blob_view(miner_bd)));
  if (blk.miner_tx.version == 2)
    num_rct_outs += blk.miner_tx.vout.size();
  int tx_i = 0;
  crypto::hash tx_hash = crypto::null_hash;
  for (const std::pair<transaction, string_blob>& tx : txs)
  {
    tx_hash = blk.tx_hashes[tx_i];
    add_transaction(blk_hash, tx, &tx_hash);
    for (const auto &vout: tx.first.vout)
    {
      if (vout.amount == 0)
        ++num_rct_outs;
    }
    ++tx_i;
  }

  // call out to subclass implementation to add the block & metadata
  add_block(blk, block_weight, long_term_block_weight, cumulative_difficulty, coins_generated, num_rct_outs, blk_hash);

  set_hard_fork_version(prev_height, config::lol::constant_hf_version);

  ++num_calls;

  return prev_height;
}

std::optional<std::pair<block, std::vector<transaction>>> BlockchainDB::pop_block()
{
  std::vector<transaction> txs;
  const auto blk = get_top_block();

  if (!blk) {
    {};
  }

  remove_block();

  for (const auto& h : boost::adaptors::reverse(blk->tx_hashes))
  {
    cryptonote::transaction tx;
    if (!get_tx(h, tx))
      throw DB_ERROR("Failed to get pruned or unpruned transaction from the db");
    txs.push_back(std::move(tx));
    remove_transaction(h);
  }
  remove_transaction(get_transaction_hash(blk->miner_tx));

  return {{*blk, txs}};
}

bool BlockchainDB::is_open() const
{
  return m_open;
}

void BlockchainDB::remove_transaction(const crypto::hash& tx_hash)
{
  transaction tx = get_tx(tx_hash);

  for (const txin_v& tx_input : tx.vin)
  {
    if (tx_input.type() == typeid(txin_from_key))
    {
      remove_spent_key(boost::get<txin_from_key>(tx_input).output_key_image);
    }
  }

  // need tx as tx.vout has the tx outputs, and the output amounts are needed
  remove_transaction_data(tx_hash, tx);
}

block BlockchainDB::get_block_from_height(const uint64_t& height) const
{
  const string_blob bd = get_block_blob_from_height(height);
  const auto maybeBlock = maybe_block_from_blob(bd);
  if (!maybeBlock) {
    throw DB_ERROR("Failed to parse block from blob retrieved from the db");
  }

  return *maybeBlock;
}

block BlockchainDB::get_block(const crypto::hash& h) const
{
  string_blob bd = get_block_blob(h);
  const auto maybeBlock = maybe_block_from_blob(bd);
  if (!maybeBlock) {
    throw DB_ERROR("Failed to parse block from blob retrieved from the db");
  }

  return *maybeBlock;
}

bool BlockchainDB::get_tx(const crypto::hash& h, cryptonote::transaction &tx) const
{
  string_blob bd;
  if (!get_tx_blob(h, bd))
    return false;
  const auto maybeTx = maybe_tx_from_blob(bd);
  if (!maybeTx) {
    throw DB_ERROR("Failed to parse transaction from blob retrieved from the db");
  }

  tx = *maybeTx;

  return true;
}

transaction BlockchainDB::get_tx(const crypto::hash& h) const
{
  transaction tx;
  if (!get_tx(h, tx))
    throw TX_DNE(std::string("tx with hash ").append(epee::string_tools::pod_to_hex(h)).append(" not found in db").c_str());
  return tx;
}

void BlockchainDB::reset_stats()
{
  num_calls = 0;
}

void BlockchainDB::show_stats()
{
  LOG_PRINT_L1(std::endl
    << "*********************************"
    << std::endl
    << "num_calls: " << num_calls
    << std::endl
    << "*********************************"
    << std::endl
  );
}

void BlockchainDB::fixup()
{
  if (is_read_only()) {
    LOG_PRINT_L1("Database is opened read only - skipping fixup check");
    return;
  }
  set_batch_transactions(true);
}

bool BlockchainDB::txpool_tx_matches_category(const crypto::hash& tx_hash, relay_category category)
{
  try
  {
    txpool_tx_meta_t meta{};
    if (!get_txpool_tx_meta(tx_hash, meta))
    {
      LOG_ERROR("Failed to get tx meta from txpool");
      return false;
    }
    return meta.matches(category);
  }
  catch (const std::exception &e)
  {
    LOG_ERROR("Failed to get tx meta from txpool: " << e.what());
  }
  return false;
}

std::unique_ptr<BlockchainDB> new_db()
{
  return std::make_unique<BlockchainLMDB>();
}

}  // namespace cryptonote
