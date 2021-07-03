// Copyright (c) 2016-2020, The Monero Project
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

#pragma once

#include "cryptonote/basic/cryptonote_basic.h"
#include "cryptonote/protocol/cryptonote_protocol_defs.h"

#include "network/rpc/message_data_structs.h"

#include "tools/epee/include/hex.h"
#include "tools/epee/include/span.h"

#include <string_view>
#include <cstring>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <vector>


#define OBJECT_HAS_MEMBER_OR_THROW(val, key) \
  do \
  { \
    if (!val.HasMember(key)) \
    { \
      throw cryptonote::json::MISSING_KEY(key); \
    } \
  } while (0);

#define INSERT_INTO_JSON_OBJECT(dest, key, source) \
    dest.Key(#key, sizeof(#key) - 1); \
    cryptonote::json::toJsonValue(dest, source);

#define GET_FROM_JSON_OBJECT(source, dst, key) \
    OBJECT_HAS_MEMBER_OR_THROW(source, #key) \
    decltype(dst) dstVal##key; \
    cryptonote::json::fromJsonValue(source[#key], dstVal##key); \
    dst = dstVal##key;

namespace cryptonote
{

namespace json
{

struct JSON_ERROR : public std::exception
{
  protected:
    JSON_ERROR() { }
    std::string m;

  public:
    virtual ~JSON_ERROR() { }

    const char* what() const throw()
    {
      return m.c_str();
    }
};

struct MISSING_KEY : public JSON_ERROR
{
  MISSING_KEY(const char* key)
  {
    m = std::string("Key \"") + key + "\" missing from object.";
  }
};

struct WRONG_TYPE : public JSON_ERROR
{
  WRONG_TYPE(const char* type)
  {
    m = std::string("Json value has incorrect type, expected: ") + type;
  }
};

struct BAD_INPUT : public JSON_ERROR
{
  BAD_INPUT()
  {
    m = "An item failed to convert from json object to native object";
  }
};

struct PARSE_FAIL : public JSON_ERROR
{
  PARSE_FAIL()
  {
    m = "Failed to parse the json request";
  }
};

template<typename Type>
constexpr bool is_to_hex()
{
  return std::is_standard_layout<Type>() && std::is_trivial<Type>() && !std::is_integral<Type>();
}

void read_hex(const rapidjson::Value& val, std::span<std::uint8_t> dest);

// POD to json key
template <class Type>
typename std::enable_if<is_to_hex<Type>()>::type toJsonKey(rapidjson::Writer<rapidjson::StringBuffer>& dest, const Type& pod)
{
  const auto hex = epee::to_hex::array(pod);
  dest.Key(hex.data(), hex.size());
}

// POD to json value
template <class Type>
typename std::enable_if<is_to_hex<Type>()>::type toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const Type& pod)
{
  const auto hex = epee::to_hex::array(pod);
  dest.String(hex.data(), hex.size());
}

template <class Type>
typename std::enable_if<is_to_hex<Type>()>::type fromJsonValue(const rapidjson::Value& val, Type& t)
{
  static_assert(std::is_standard_layout<Type>(), "expected standard layout type");
  json::read_hex(val, epee::as_mut_byte_span(t));
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const rapidjson::Value& src);
void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const std::string_view i);
void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const std::string& i);

void fromJsonValue(const rapidjson::Value& val, std::string& str);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, bool i);
void fromJsonValue(const rapidjson::Value& val, bool& b);

// integers overloads for toJsonValue are not needed for standard promotions

void fromJsonValue(const rapidjson::Value& val, unsigned char& i);

void fromJsonValue(const rapidjson::Value& val, signed char& i);

void fromJsonValue(const rapidjson::Value& val, char& i);

void fromJsonValue(const rapidjson::Value& val, unsigned short& i);

void fromJsonValue(const rapidjson::Value& val, short& i);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const unsigned i);
void fromJsonValue(const rapidjson::Value& val, unsigned& i);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const int);
void fromJsonValue(const rapidjson::Value& val, int& i);


void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const unsigned long long i);
void fromJsonValue(const rapidjson::Value& val, unsigned long long& i);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const long long i);
void fromJsonValue(const rapidjson::Value& val, long long& i);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const unsigned long i);

void fromJsonValue(const rapidjson::Value& val, unsigned long& i);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const long i);
void fromJsonValue(const rapidjson::Value& val, long& i);

// end integers

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::transaction& tx);
void fromJsonValue(const rapidjson::Value& val, cryptonote::transaction& tx);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::block& b);
void fromJsonValue(const rapidjson::Value& val, cryptonote::block& b);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::txin_v& txin);
void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_v& txin);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::txin_gen& txin);
void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_gen& txin);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::txin_to_script& txin);
void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_to_script& txin);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::txin_to_scripthash& txin);
void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_to_scripthash& txin);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::txin_to_key& txin);
void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_to_key& txin);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::txout_target_v& txout);
void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_target_v& txout);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::txout_to_script& txout);
void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_to_script& txout);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::txout_to_scripthash& txout);
void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_to_scripthash& txout);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::txout_to_key& txout);
void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_to_key& txout);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::tx_out& txout);
void fromJsonValue(const rapidjson::Value& val, cryptonote::tx_out& txout);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::connection_info& info);
void fromJsonValue(const rapidjson::Value& val, cryptonote::connection_info& info);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::tx_blob_entry& tx);
void fromJsonValue(const rapidjson::Value& val, cryptonote::tx_blob_entry& tx);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::block_complete_entry& blk);
void fromJsonValue(const rapidjson::Value& val, cryptonote::block_complete_entry& blk);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::block_with_transactions& blk);
void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::block_with_transactions& blk);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::transaction_info& tx_info);
void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::transaction_info& tx_info);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::output_key_and_amount_index& out);
void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_key_and_amount_index& out);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::amount_with_random_outputs& out);
void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::amount_with_random_outputs& out);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::peer& peer);
void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::peer& peer);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::tx_in_pool& tx);
void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::tx_in_pool& tx);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::output_amount_count& out);
void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_amount_count& out);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::output_amount_and_index& out);
void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_amount_and_index& out);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::output_key_mask_unlocked& out);
void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_key_mask_unlocked& out);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::error& err);
void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::error& error);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::BlockHeaderResponse& response);
void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::BlockHeaderResponse& response);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const rct::rctSig& i);
void fromJsonValue(const rapidjson::Value& val, rct::rctSig& sig);

void fromJsonValue(const rapidjson::Value& val, rct::ctkey& key);
void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const rct::ecdhTuple& tuple);
void fromJsonValue(const rapidjson::Value& val, rct::ecdhTuple& tuple);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const rct::Bulletproof& p);
void fromJsonValue(const rapidjson::Value& val, rct::Bulletproof& p);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::DaemonInfo& info);
void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::DaemonInfo& info);

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::output_distribution& dist);
void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_distribution& dist);

template <typename T>
void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const std::list<T> &xs)
{
  dest.StartArray();
  for (const auto& t : xs)
    toJsonValue(dest, t);
  dest.EndArray();
}

template <typename T>
void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const std::vector<T> &xs)
{
  dest.StartArray();
  for (const auto& t : xs)
    toJsonValue(dest, t);
  dest.EndArray();
}

template <typename T>
void fromJsonValue(const rapidjson::Value& val, std::vector<T>& xs)
{
  if (!val.IsArray()) {
    throw WRONG_TYPE("json array");
  }

  xs.clear();
  xs.reserve(val.Size());
  T v;
  for (rapidjson::SizeType i=0; i < val.Size(); i++)
  {
    fromJsonValue(val[i], v);
    xs.emplace_back(v);
  }
}

template <typename T>
void fromJsonValue(const rapidjson::Value& val, std::list<T>& xs)
{
  if (!val.IsArray()) {
    throw WRONG_TYPE("json array");
  }

  xs.clear();
  T v;
  for (rapidjson::SizeType i=0; i < val.Size(); i++)
  {
    fromJsonValue(val[i], v);
    xs.emplace_back(v);
  }
}

template <typename K, typename V>
void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const std::map<K, V>& map)
{
  using key_type = K;
  static_assert(std::is_same<std::string, key_type>() || is_to_hex<key_type>(), "invalid map key type");

  dest.StartObject();
  for (const auto &[k,v] : map)
  {
    toJsonKey(dest, k);
    toJsonValue(dest, v);
  }
  dest.EndObject();
}


template <typename K, typename V>
void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const std::unordered_map<K, V>& map)
{
  using key_type = K;
  static_assert(std::is_same<std::string, key_type>() || is_to_hex<key_type>(), "invalid map key type");

  dest.StartObject();
  for (const auto &[k,v] : map)
  {
    toJsonKey(dest, k);
    toJsonValue(dest, v);
  }
  dest.EndObject();
}

template <typename K, typename V>
void fromJsonValue(const rapidjson::Value& val, std::map<K, V>& map)
{
  if (!val.IsObject()) {
    throw WRONG_TYPE("json object");
  }

  auto itr = val.MemberBegin();

  map.clear();
  K k;
  V v;
  while (itr != val.MemberEnd())
  {
    fromJsonValue(itr->name, k);
    fromJsonValue(itr->value, v);
    map.emplace(k, v);
    ++itr;
  }
}

template <typename K, typename V>
void fromJsonValue(const rapidjson::Value& val, std::unordered_map<K, V>& map)
{
  if (!val.IsObject()) {
    throw WRONG_TYPE("json object");
  }

  auto itr = val.MemberBegin();

  map.clear();
  K k;
  V v;
  while (itr != val.MemberEnd())
  {
    fromJsonValue(itr->name, k);
    fromJsonValue(itr->value, v);
    map.emplace(k, v);
    ++itr;
  }
}

}  // namespace json

}  // namespace cryptonote
