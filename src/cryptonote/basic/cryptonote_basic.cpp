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

#include "cryptonote_basic.h"

#include "functional/format_utils.hpp"

namespace cryptonote
{
  std::optional<spend_view_public_keys> maybe_safe_spend_view_public_keys(const spend_view_public_keys_unsafe x)
  {
    const auto spend_pk = maybeSafePoint(x.m_spend_public_key_unsafe);
    const auto view_pk = maybeSafePoint(x.m_view_public_key_unsafe);

    if (spend_pk && view_pk) {
      return {{*spend_pk, *view_pk}};
    }
    else {
      return {};
    }
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

  //--------------------------------------------------------------------------------
  bool operator ==(const cryptonote::transaction& a, const cryptonote::transaction& b) {
    return cryptonote::get_transaction_hash(a) == cryptonote::get_transaction_hash(b);
  }

  bool operator ==(const cryptonote::block& a, const cryptonote::block& b) {
    return cryptonote::get_block_hash(a) == cryptonote::get_block_hash(b);
  }

  //--------------------------------------------------------------------------------
  std::optional<crypto::hash> parse_hash256(const std::string &str_hash)
  {
    std::string buf;
    crypto::hash hash;
    bool res = epee::string_tools::parse_hexstr_to_binbuff(str_hash, buf);
    if (!res || buf.size() != hash.data.size())
    {
      LOG_ERROR("invalid hash format: " << str_hash);
      return {};
    }
    else
    {
      std::copy(buf.begin(), buf.end(), hash.data.begin());
      return hash;
    }
  }


  //--------------------------------------------------------------------------------
  std::optional<crypto::crypto_data> parse_crypto_data(const std::string str_hash)
  {
    std::string buf;
    crypto::crypto_data out;
    bool res = epee::string_tools::parse_hexstr_to_binbuff(str_hash, buf);
    if (!res || buf.size() != out.data.size())
    {
      LOG_ERROR("invalid hash format: " << str_hash);
      return {};
    }
    else
    {
      std::copy(buf.begin(), buf.end(), out.data.begin());
      return out;
    }
  }
}
