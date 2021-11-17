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

#include "../controller/format_utils.hpp"

#include "tools/epee/include/string_tools.h"
#include "tools/serialization/string.h" // don't remove, or face core dump

#include "math/ringct/pseudo_functional/rctSigs.hpp"

#include "cryptonote/basic/functional/subaddress.hpp"

#include <boost/algorithm/string.hpp>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "cn"

using namespace constant;

static std::atomic<unsigned int> default_decimal_point(CRYPTONOTE_DISPLAY_DECIMAL_POINT);

static std::atomic<uint64_t> tx_hashes_calculated_count(0);
static std::atomic<uint64_t> tx_hashes_cached_count(0);
static std::atomic<uint64_t> block_hashes_calculated_count(0);
static std::atomic<uint64_t> block_hashes_cached_count(0);

namespace cryptonote
{
  //---------------------------------------------------------------
  std::optional<transaction> expand_transaction(const transaction &tx_in, bool base_only)
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
        ("Failed to parse transaction from blob, bad output_commits size in tx " << get_transaction_hash(tx));
      return {};
    }

    if (base_only) return tx;

    if (rv.p.bulletproofs.size() != 1)
    {
      LOG_PRINT_L1
        ("Failed to parse transaction from blob, bad bulletproofs size in tx " << get_transaction_hash(tx));
      return {};
    }

    if (rv.p.bulletproofs[0].L.size() < 6)
    {
      LOG_PRINT_L1
        ("Failed to parse transaction from blob, bad bulletproofs L size in tx " << get_transaction_hash(tx));
      return {};
    }

    const size_t max_outputs = 1 << (rv.p.bulletproofs[0].L.size() - 6);
    if (max_outputs < tx.vout.size())
    {
      LOG_PRINT_L1
        ("Failed to parse transaction from blob, bad bulletproofs max outputs in tx " << get_transaction_hash(tx));
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
  std::optional<transaction> maybe_tx_from_blob(const blobdata_ref tx_blob)
  {
    const transaction dummyTx;
    const auto maybeTx = maybe_from_blob(tx_blob, dummyTx);
    LOG_ERROR_AND_RETURN_UNLESS(maybeTx, {}, "Failed to parse transaction from blob");
    const auto maybeExpandedTx = expand_transaction(*maybeTx, false);
    LOG_ERROR_AND_RETURN_UNLESS(maybeExpandedTx, {}, "Failed to expand transaction data");
    return *maybeExpandedTx;
  }

  //---------------------------------------------------------------
  bool parse_and_validate_tx_prefix_from_blob(const blobdata_ref tx_blob, transaction_prefix& tx)
  {
    std::stringstream ss;
    ss << tx_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize_noeof(ba, tx);
    LOG_ERROR_AND_RETURN_UNLESS(r, false, "Failed to parse transaction prefix from blob");
    return true;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_tx_from_blob(const blobdata_ref tx_blob, transaction& tx, crypto::hash& tx_hash)
  {
    std::stringstream ss;
    ss << tx_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, tx);
    LOG_ERROR_AND_RETURN_UNLESS(r, false, "Failed to parse transaction from blob");

    const auto maybeTx = expand_transaction(tx, false);
    LOG_ERROR_AND_RETURN_UNLESS(maybeTx, false, "Failed to expand transaction data");
    tx = *maybeTx;
    
    //TODO: validate tx

    tx_hash = get_transaction_hash(tx);
    return true;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_tx_from_blob(const blobdata_ref tx_blob, transaction& tx, crypto::hash& tx_hash, crypto::hash& tx_prefix_hash)
  {
    if (!parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash))
      return false;
    tx_prefix_hash = get_transaction_prefix_hash(tx);
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
  bool parse_and_validate_block_from_blob(const blobdata_ref b_blob, block& b, crypto::hash *block_hash)
  {
    std::stringstream ss;
    ss << b_blob;
    binary_archive<false> ba(ss);
    bool r = ::serialization::serialize(ba, b);
    LOG_ERROR_AND_RETURN_UNLESS(r, false, "Failed to parse block from blob");
    if (block_hash)
    {
      *block_hash = get_block_hash(b);
    }
    return true;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_block_from_blob(const blobdata_ref b_blob, block& b)
  {
    return parse_and_validate_block_from_blob(b_blob, b, NULL);
  }
  //---------------------------------------------------------------
  bool parse_and_validate_block_from_blob(const blobdata_ref b_blob, block& b, crypto::hash &block_hash)
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
    const auto blob = maybe_to_blob(b);
    if (blob) {
      b_blob = *blob;
      return true;
    } else {
      return false;
    }
  }
  //---------------------------------------------------------------
  blobdata tx_to_blob(const transaction& tx)
  {
    return t_serializable_object_to_blob(tx);
  }
  //---------------------------------------------------------------
  bool tx_to_blob(const transaction& tx, blobdata& b_blob)
  {
    const auto blob = maybe_to_blob(tx);

    if (blob) {
      b_blob = *blob;
      return true;
    } else {
      return false;
    }
  }
  //---------------------------------------------------------------
  void get_hash_stats(uint64_t &tx_hashes_calculated, uint64_t &tx_hashes_cached, uint64_t &block_hashes_calculated, uint64_t & block_hashes_cached)
  {
    tx_hashes_calculated = tx_hashes_calculated_count;
    tx_hashes_cached = tx_hashes_cached_count;
    block_hashes_calculated = block_hashes_calculated_count;
    block_hashes_cached = block_hashes_cached_count;
  }

}
