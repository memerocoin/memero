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
  std::optional<uint64_t> parse_amount(const std::string& str_amount_)
  {
    uint64_t amount;
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
        return {};
      str_amount.erase(point_index, 1);
    }
    else
    {
      fraction_size = 0;
    }

    if (str_amount.empty())
      return {};

    if (fraction_size < default_decimal_point)
    {
      str_amount.append(default_decimal_point - fraction_size, '0');
    }

    const auto r = epee::string_tools::get_xtype_from_string(amount, str_amount);
    if (r) {
      return amount;
    } else {
      return {};
    }
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
  bool parse_and_validate_block_from_blob(const blobdata_ref b_blob, block& b, crypto::hash &block_hash)
  {
    const auto maybeBlock = maybe_block_from_blob(b_blob);
    if (maybeBlock) {
      b = *maybeBlock;
      block_hash = get_block_hash(b);
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
