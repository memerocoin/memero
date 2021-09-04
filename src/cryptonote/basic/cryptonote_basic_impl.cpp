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


#include "tools/common/base58.h"
#include "tools/epee/include/string_tools.h"
#include "tools/serialization/binary_utils.h"


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "cn"

using namespace epee;
using namespace constant;

namespace cryptonote {
  //------------------------------------------------------------------------------------
  uint8_t get_account_address_checksum(const public_address_outer_blob& bl)
  {
    const auto buf = epee::pod_to_span(bl);
    const auto buf_data = buf.subspan(0, buf.size() - 1);

    return std::reduce(buf_data.begin(), buf_data.end());
  }
  //------------------------------------------------------------------------------------
  std::string get_account_address_as_str(
      const network_type nettype
    , const bool subaddress
    , const account_public_address & adr
    )
  {
    uint64_t address_prefix = subaddress ? get_config(nettype).CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX : get_config(nettype).CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;

    return tools::base58::encode_addr(address_prefix, t_serializable_object_to_blob(adr));
  }
  //-----------------------------------------------------------------------
  bool is_coinbase(const transaction& tx)
  {
    if(tx.vin.size() != 1)
      return false;

    if(tx.vin[0].type() != typeid(txin_gen))
      return false;

    return true;
  }
  //-----------------------------------------------------------------------
  bool get_account_address_from_str(
      address_parse_info& info
    , network_type nettype
    , std::string const & str
    )
  {
    uint64_t address_prefix = get_config(nettype).CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
    uint64_t subaddress_prefix = get_config(nettype).CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;

    if (2 * sizeof(public_address_outer_blob) != str.size())
    {
      blobdata data;
      uint64_t prefix;
      if (!tools::base58::decode_addr(str, prefix, data))
      {
        LOG_PRINT_L2("Invalid address format");
        return false;
      }
      else if (address_prefix == prefix)
      {
        info.is_subaddress = false;
      }
      else if (subaddress_prefix == prefix)
      {
        info.is_subaddress = true;
      }
      else {
        LOG_PRINT_L1("Wrong address prefix: " << prefix << ", expected " << address_prefix
          << " or " << subaddress_prefix);
        return false;
      }

      {
        if (!::serialization::parse_binary(data, info.address))
        {
          LOG_PRINT_L1("Account public address keys can't be parsed");
          return false;
        }
      }

      if (!crypto::is_valid_ec_point(info.address.m_spend_public_key) || !crypto::is_valid_ec_point(info.address.m_view_public_key))
      {
        LOG_PRINT_L1("Failed to validate address keys");
        return false;
      }

      return true;
    }
    return false;
  }
  //--------------------------------------------------------------------------------
  bool get_account_address_from_str_or_url(
      address_parse_info& info
    , network_type nettype
    , const std::string& str_or_url
    )
  {
    if (get_account_address_from_str(info, nettype, str_or_url))
      return true;
    std::string address_str;
    return !address_str.empty() &&
      get_account_address_from_str(info, nettype, address_str);
  }
  //--------------------------------------------------------------------------------
  bool operator ==(const cryptonote::transaction& a, const cryptonote::transaction& b) {
    return cryptonote::get_transaction_hash(a) == cryptonote::get_transaction_hash(b);
  }

  bool operator ==(const cryptonote::block& a, const cryptonote::block& b) {
    return cryptonote::get_block_hash(a) == cryptonote::get_block_hash(b);
  }
}

//--------------------------------------------------------------------------------
bool parse_hash256(const std::string &str_hash, crypto::hash& hash)
{
  std::string buf;
  bool res = epee::string_tools::parse_hexstr_to_binbuff(str_hash, buf);
  if (!res || buf.size() != hash.data.size())
  {
    LOG_ERROR("invalid hash format: " << str_hash);
    return false;
  }
  else
  {
    std::copy(buf.begin(), buf.end(), hash.data.begin());
    return true;
  }
}
