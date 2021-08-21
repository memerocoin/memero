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

#include "json_object.h"

#include "cryptonote/basic/cryptonote_basic_impl.h"

#include <limits>
#include <type_traits>

#include <boost/variant/apply_visitor.hpp>

namespace cryptonote
{

namespace json
{

namespace
{
  template<typename Source, typename Destination>
  constexpr bool precision_loss()
  {
    return
      std::numeric_limits<Destination>::is_signed != std::numeric_limits<Source>::is_signed ||
      std::numeric_limits<Destination>::min() > std::numeric_limits<Source>::min() ||
      std::numeric_limits<Destination>::max() < std::numeric_limits<Source>::max();
  }

  template<typename Source, typename Type>
  void convert_numeric(Source source, Type& i)
  {
    static_assert(
      (std::is_same<Type, char>() && std::is_same<Source, int>()) ||
      std::numeric_limits<Source>::is_signed == std::numeric_limits<Type>::is_signed,
      "comparisons below may have undefined behavior"
    );
    if (source < std::numeric_limits<Type>::min())
    {
      throw WRONG_TYPE{"numeric underflow"};
    }
    if (std::numeric_limits<Type>::max() < source)
    {
      throw WRONG_TYPE{"numeric overflow"};
    }
    i = Type(source);
  }

  template<typename Type>
  void to_int(const rapidjson::Value& val, Type& i)
  {
    if (!val.IsInt())
    {
      throw WRONG_TYPE{"integer"};
    }
    convert_numeric(val.GetInt(), i);
  }
  template<typename Type>
  void to_int64(const rapidjson::Value& val, Type& i)
  {
    if (!val.IsInt64())
    {
      throw WRONG_TYPE{"integer"};
    }
    convert_numeric(val.GetInt64(), i);
  }

  template<typename Type>
  void to_uint(const rapidjson::Value& val, Type& i)
  {
    if (!val.IsUint())
    {
      throw WRONG_TYPE{"unsigned integer"};
    }
    convert_numeric(val.GetUint(), i);
  }
  template<typename Type>
  void to_uint64(const rapidjson::Value& val, Type& i)
  {
    if (!val.IsUint64())
    {
      throw WRONG_TYPE{"unsigned integer"};
    }
    convert_numeric(val.GetUint64(), i);
  }
}

void read_hex(const rapidjson::Value& val, std::span<std::uint8_t> dest)
{
  if (!val.IsString())
  {
    throw WRONG_TYPE("string");
  }

  if (!epee::hex::to_span(dest, {val.GetString(), val.GetStringLength()}))
  {
    throw BAD_INPUT();
  }
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const rapidjson::Value& src)
{
  src.Accept(dest);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const std::string_view i)
{
  dest.String(i.data(), i.size());
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const std::string i)
{
  toJsonValue(dest, std::string_view{i});
}

void fromJsonValue(const rapidjson::Value& val, std::string& str)
{
  if (!val.IsString())
  {
    throw WRONG_TYPE("string");
  }

  str = val.GetString();
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const bool i)
{
  dest.Bool(i);
}

void fromJsonValue(const rapidjson::Value& val, bool& b)
{
  if (!val.IsBool())
  {
    throw WRONG_TYPE("boolean");
  }
  b = val.GetBool();
}

void fromJsonValue(const rapidjson::Value& val, unsigned char& i)
{
  to_uint(val, i);
}

void fromJsonValue(const rapidjson::Value& val, char& i)
{
  to_int(val, i);
}

void fromJsonValue(const rapidjson::Value& val, signed char& i)
{
  to_int(val, i);
}

void fromJsonValue(const rapidjson::Value& val, unsigned short& i)
{
  to_uint(val, i);
}

void fromJsonValue(const rapidjson::Value& val, short& i)
{
  to_int(val, i);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const unsigned int i)
{
  dest.Uint(i);
}

void fromJsonValue(const rapidjson::Value& val, unsigned int& i)
{
  to_uint(val, i);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const int i)
{
  dest.Int(i);
}

void fromJsonValue(const rapidjson::Value& val, int& i)
{
  to_int(val, i);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const unsigned long long i)
{
  static_assert(!precision_loss<unsigned long long, std::uint64_t>(), "bad uint64 conversion");
  dest.Uint64(i);
}

void fromJsonValue(const rapidjson::Value& val, unsigned long long& i)
{
  to_uint64(val, i);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const long long i)
{
  static_assert(!precision_loss<long long, std::int64_t>(), "bad int64 conversion");
  dest.Int64(i);
}

void fromJsonValue(const rapidjson::Value& val, long long& i)
{
  to_int64(val, i);
}


void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const unsigned long i) {
  toJsonValue(dest, static_cast<const unsigned long long>(i));
}

void fromJsonValue(const rapidjson::Value& val, unsigned long& i)
{
  to_uint64(val, i);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const long i) {
  toJsonValue(dest, static_cast<const long long>(i));
}

void fromJsonValue(const rapidjson::Value& val, long& i)
{
  to_int64(val, i);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::transaction tx)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, version, tx.version);
  WRITE_JSON_FIELD_FROM(dest, unlock_time, tx.unlock_time);
  WRITE_JSON_FIELD_FROM(dest, inputs, tx.vin);
  WRITE_JSON_FIELD_FROM(dest, outputs, tx.vout);
  WRITE_JSON_FIELD_FROM(dest, extra, tx.extra);
  WRITE_JSON_FIELD_FROM(dest, signatures, tx.signatures);
  WRITE_JSON_FIELD_FROM(dest, ringct, tx.rct_signatures);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::transaction& tx)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, tx.version, version);
  READ_JSON_VALUE_BY_KEY(val, tx.unlock_time, unlock_time);
  READ_JSON_VALUE_BY_KEY(val, tx.vin, inputs);
  READ_JSON_VALUE_BY_KEY(val, tx.vout, outputs);
  READ_JSON_VALUE_BY_KEY(val, tx.extra, extra);
  READ_JSON_VALUE_BY_KEY(val, tx.rct_signatures, ringct);

  const auto& sigs = val.FindMember("signatures");
  if (sigs != val.MemberEnd())
  {
    fromJsonValue(sigs->value, tx.signatures);
  }
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::block b)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, major_version, b.major_version);
  WRITE_JSON_FIELD_FROM(dest, minor_version, b.minor_version);
  WRITE_JSON_FIELD_FROM(dest, timestamp, b.timestamp);
  WRITE_JSON_FIELD_FROM(dest, prev_id, b.prev_id);
  WRITE_JSON_FIELD_FROM(dest, nonce, b.nonce);
  WRITE_JSON_FIELD_FROM(dest, miner_tx, b.miner_tx);
  WRITE_JSON_FIELD_FROM(dest, tx_hashes, b.tx_hashes);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::block& b)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, b.major_version, major_version);
  READ_JSON_VALUE_BY_KEY(val, b.minor_version, minor_version);
  READ_JSON_VALUE_BY_KEY(val, b.timestamp, timestamp);
  READ_JSON_VALUE_BY_KEY(val, b.prev_id, prev_id);
  READ_JSON_VALUE_BY_KEY(val, b.nonce, nonce);
  READ_JSON_VALUE_BY_KEY(val, b.miner_tx, miner_tx);
  READ_JSON_VALUE_BY_KEY(val, b.tx_hashes, tx_hashes);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::txin_v txin)
{
  dest.StartObject();
  struct add_input
  {
    using result_type = void;

    rapidjson::Writer<rapidjson::StringBuffer>& dest;

    void operator()(cryptonote::txin_to_key const& input) const
    {
      WRITE_JSON_FIELD_FROM(dest, to_key, input);
    }
    void operator()(cryptonote::txin_gen const& input) const
    {
      WRITE_JSON_FIELD_FROM(dest, gen, input);
    }
    void operator()(cryptonote::txin_to_script const& input) const
    {
      WRITE_JSON_FIELD_FROM(dest, to_script, input);
    }
    void operator()(cryptonote::txin_to_scripthash const& input) const
    {
      WRITE_JSON_FIELD_FROM(dest, to_scripthash, input);
    }
  };
  boost::apply_visitor(add_input{dest}, txin);
  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_v& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  if (val.MemberCount() != 1)
  {
    throw MISSING_KEY("Invalid input object");
  }

  for (auto const& elem : val.GetObject())
  {
    if (elem.name == "to_key")
    {
      cryptonote::txin_to_key tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txin = std::move(tmpVal);
    }
    else if (elem.name == "gen")
    {
      cryptonote::txin_gen tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txin = std::move(tmpVal);
    }
    else if (elem.name == "to_script")
    {
      cryptonote::txin_to_script tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txin = std::move(tmpVal);
    }
    else if (elem.name == "to_scripthash")
    {
      cryptonote::txin_to_scripthash tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txin = std::move(tmpVal);
    }
  }
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::txin_gen txin)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, height, txin.height);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_gen& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, txin.height, height);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::txin_to_script txin)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, prev, txin.prev);
  WRITE_JSON_FIELD_FROM(dest, prevout, txin.prevout);
  WRITE_JSON_FIELD_FROM(dest, sigset, txin.sigset);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_to_script& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, txin.prev, prev);
  READ_JSON_VALUE_BY_KEY(val, txin.prevout, prevout);
  READ_JSON_VALUE_BY_KEY(val, txin.sigset, sigset);
}


void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::txin_to_scripthash txin)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, prev, txin.prev);
  WRITE_JSON_FIELD_FROM(dest, prevout, txin.prevout);
  WRITE_JSON_FIELD_FROM(dest, script, txin.script);
  WRITE_JSON_FIELD_FROM(dest, sigset, txin.sigset);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_to_scripthash& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, txin.prev, prev);
  READ_JSON_VALUE_BY_KEY(val, txin.prevout, prevout);
  READ_JSON_VALUE_BY_KEY(val, txin.script, script);
  READ_JSON_VALUE_BY_KEY(val, txin.sigset, sigset);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::txin_to_key txin)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, amount, txin.amount);
  WRITE_JSON_FIELD_FROM(dest, key_offsets, txin.key_offsets);
  WRITE_JSON_FIELD_FROM(dest, key_image, txin.k_image);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_to_key& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, txin.amount, amount);
  READ_JSON_VALUE_BY_KEY(val, txin.key_offsets, key_offsets);
  READ_JSON_VALUE_BY_KEY(val, txin.k_image, key_image);
}


void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::txout_to_script txout)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, keys, txout.keys);
  WRITE_JSON_FIELD_FROM(dest, script, txout.script);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_to_script& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, txout.keys, keys);
  READ_JSON_VALUE_BY_KEY(val, txout.script, script);
}


void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::txout_to_scripthash txout)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, hash, txout.hash);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_to_scripthash& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, txout.hash, hash);
}


void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::txout_to_key txout)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, key, txout.key);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_to_key& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, txout.key, key);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::tx_out txout)
{
  dest.StartObject();
  WRITE_JSON_FIELD_FROM(dest, amount, txout.amount);

  struct add_output
  {
    using result_type = void;

    rapidjson::Writer<rapidjson::StringBuffer>& dest;

    void operator()(cryptonote::txout_to_key const& output) const
    {
      WRITE_JSON_FIELD_FROM(dest, to_key, output);
    }
    void operator()(cryptonote::txout_to_script const& output) const
    {
      WRITE_JSON_FIELD_FROM(dest, to_script, output);
    }
    void operator()(cryptonote::txout_to_scripthash const& output) const
    {
      WRITE_JSON_FIELD_FROM(dest, to_scripthash, output);
    }
  };
  boost::apply_visitor(add_output{dest}, txout.target);
   dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::tx_out& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  if (val.MemberCount() != 2)
  {
    throw MISSING_KEY("Invalid input object");
  }

  for (auto const& elem : val.GetObject())
  {
    if (elem.name == "amount")
    {
      fromJsonValue(elem.value, txout.amount);
    }

    if (elem.name == "to_key")
    {
      cryptonote::txout_to_key tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txout.target = std::move(tmpVal);
    }
    else if (elem.name == "to_script")
    {
      cryptonote::txout_to_script tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txout.target = std::move(tmpVal);
    }
    else if (elem.name == "to_scripthash")
    {
      cryptonote::txout_to_scripthash tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txout.target = std::move(tmpVal);
    }
  }
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::connection_info info)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, incoming, info.incoming);
  WRITE_JSON_FIELD_FROM(dest, localhost, info.localhost);
  WRITE_JSON_FIELD_FROM(dest, local_ip, info.local_ip);
  WRITE_JSON_FIELD_FROM(dest, address_type, info.address_type);

  WRITE_JSON_FIELD_FROM(dest, ip, info.ip);
  WRITE_JSON_FIELD_FROM(dest, port, info.port);
  WRITE_JSON_FIELD_FROM(dest, rpc_port, info.rpc_port);

  WRITE_JSON_FIELD_FROM(dest, peer_id, info.peer_id);

  WRITE_JSON_FIELD_FROM(dest, recv_count, info.recv_count);
  WRITE_JSON_FIELD_FROM(dest, recv_idle_time, info.recv_idle_time);

  WRITE_JSON_FIELD_FROM(dest, send_count, info.send_count);
  WRITE_JSON_FIELD_FROM(dest, send_idle_time, info.send_idle_time);

  WRITE_JSON_FIELD_FROM(dest, state, info.state);

  WRITE_JSON_FIELD_FROM(dest, live_time, info.live_time);

  WRITE_JSON_FIELD_FROM(dest, avg_download, info.avg_download);
  WRITE_JSON_FIELD_FROM(dest, current_download, info.current_download);

  WRITE_JSON_FIELD_FROM(dest, avg_upload, info.avg_upload);
  WRITE_JSON_FIELD_FROM(dest, current_upload, info.current_upload);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::connection_info& info)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, info.incoming, incoming);
  READ_JSON_VALUE_BY_KEY(val, info.localhost, localhost);
  READ_JSON_VALUE_BY_KEY(val, info.local_ip, local_ip);
  READ_JSON_VALUE_BY_KEY(val, info.address_type, address_type);

  READ_JSON_VALUE_BY_KEY(val, info.ip, ip);
  READ_JSON_VALUE_BY_KEY(val, info.port, port);
  READ_JSON_VALUE_BY_KEY(val, info.rpc_port, rpc_port);

  READ_JSON_VALUE_BY_KEY(val, info.peer_id, peer_id);

  READ_JSON_VALUE_BY_KEY(val, info.recv_count, recv_count);
  READ_JSON_VALUE_BY_KEY(val, info.recv_idle_time, recv_idle_time);

  READ_JSON_VALUE_BY_KEY(val, info.send_count, send_count);
  READ_JSON_VALUE_BY_KEY(val, info.send_idle_time, send_idle_time);

  READ_JSON_VALUE_BY_KEY(val, info.state, state);

  READ_JSON_VALUE_BY_KEY(val, info.live_time, live_time);

  READ_JSON_VALUE_BY_KEY(val, info.avg_download, avg_download);
  READ_JSON_VALUE_BY_KEY(val, info.current_download, current_download);

  READ_JSON_VALUE_BY_KEY(val, info.avg_upload, avg_upload);
  READ_JSON_VALUE_BY_KEY(val, info.current_upload, current_upload);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::tx_blob_entry tx)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, blob, tx.blob);
  WRITE_JSON_FIELD_FROM(dest, prunable_hash, tx.prunable_hash);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::tx_blob_entry& tx)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, tx.blob, blob);
  READ_JSON_VALUE_BY_KEY(val, tx.prunable_hash, prunable_hash);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::block_complete_entry blk)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, block, blk.block);
  WRITE_JSON_FIELD_FROM(dest, transactions, blk.txs);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::block_complete_entry& blk)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, blk.block, block);
  READ_JSON_VALUE_BY_KEY(val, blk.txs, transactions);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::block_with_transactions blk)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, block, blk.block);
  WRITE_JSON_FIELD_FROM(dest, transactions, blk.transactions);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::block_with_transactions& blk)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, blk.block, block);
  READ_JSON_VALUE_BY_KEY(val, blk.transactions, transactions);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::transaction_info tx_info)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, height, tx_info.height);
  WRITE_JSON_FIELD_FROM(dest, in_pool, tx_info.in_pool);
  WRITE_JSON_FIELD_FROM(dest, transaction, tx_info.transaction);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::transaction_info& tx_info)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, tx_info.height, height);
  READ_JSON_VALUE_BY_KEY(val, tx_info.in_pool, in_pool);
  READ_JSON_VALUE_BY_KEY(val, tx_info.transaction, transaction);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::output_key_and_amount_index out)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, amount_index, out.amount_index);
  WRITE_JSON_FIELD_FROM(dest, key, out.key);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_key_and_amount_index& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, out.amount_index, amount_index);
  READ_JSON_VALUE_BY_KEY(val, out.key, key);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::amount_with_random_outputs out)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, amount, out.amount);
  WRITE_JSON_FIELD_FROM(dest, outputs, out.outputs);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::amount_with_random_outputs& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, out.amount, amount);
  READ_JSON_VALUE_BY_KEY(val, out.outputs, outputs);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::peer peer)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, id, peer.id);
  WRITE_JSON_FIELD_FROM(dest, ip, peer.ip);
  WRITE_JSON_FIELD_FROM(dest, port, peer.port);
  WRITE_JSON_FIELD_FROM(dest, rpc_port, peer.rpc_port);
  WRITE_JSON_FIELD_FROM(dest, last_seen, peer.last_seen);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::peer& peer)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, peer.id, id);
  READ_JSON_VALUE_BY_KEY(val, peer.ip, ip);
  READ_JSON_VALUE_BY_KEY(val, peer.port, port);
  READ_JSON_VALUE_BY_KEY(val, peer.rpc_port, rpc_port);
  READ_JSON_VALUE_BY_KEY(val, peer.last_seen, last_seen);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::tx_in_pool tx)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, tx, tx.tx);
  WRITE_JSON_FIELD_FROM(dest, tx_hash, tx.tx_hash);
  WRITE_JSON_FIELD_FROM(dest, blob_size, tx.blob_size);
  WRITE_JSON_FIELD_FROM(dest, weight, tx.weight);
  WRITE_JSON_FIELD_FROM(dest, fee, tx.fee);
  WRITE_JSON_FIELD_FROM(dest, max_used_block_hash, tx.max_used_block_hash);
  WRITE_JSON_FIELD_FROM(dest, max_used_block_height, tx.max_used_block_height);
  WRITE_JSON_FIELD_FROM(dest, kept_by_block, tx.kept_by_block);
  WRITE_JSON_FIELD_FROM(dest, last_failed_block_hash, tx.last_failed_block_hash);
  WRITE_JSON_FIELD_FROM(dest, last_failed_block_height, tx.last_failed_block_height);
  WRITE_JSON_FIELD_FROM(dest, receive_time, tx.receive_time);
  WRITE_JSON_FIELD_FROM(dest, last_relayed_time, tx.last_relayed_time);
  WRITE_JSON_FIELD_FROM(dest, relayed, tx.relayed);
  WRITE_JSON_FIELD_FROM(dest, do_not_relay, tx.do_not_relay);
  WRITE_JSON_FIELD_FROM(dest, double_spend_seen, tx.double_spend_seen);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::tx_in_pool& tx)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, tx.tx, tx);
  READ_JSON_VALUE_BY_KEY(val, tx.blob_size, blob_size);
  READ_JSON_VALUE_BY_KEY(val, tx.weight, weight);
  READ_JSON_VALUE_BY_KEY(val, tx.fee, fee);
  READ_JSON_VALUE_BY_KEY(val, tx.max_used_block_hash, max_used_block_hash);
  READ_JSON_VALUE_BY_KEY(val, tx.max_used_block_height, max_used_block_height);
  READ_JSON_VALUE_BY_KEY(val, tx.kept_by_block, kept_by_block);
  READ_JSON_VALUE_BY_KEY(val, tx.last_failed_block_hash, last_failed_block_hash);
  READ_JSON_VALUE_BY_KEY(val, tx.last_failed_block_height, last_failed_block_height);
  READ_JSON_VALUE_BY_KEY(val, tx.receive_time, receive_time);
  READ_JSON_VALUE_BY_KEY(val, tx.last_relayed_time, last_relayed_time);
  READ_JSON_VALUE_BY_KEY(val, tx.relayed, relayed);
  READ_JSON_VALUE_BY_KEY(val, tx.do_not_relay, do_not_relay);
  READ_JSON_VALUE_BY_KEY(val, tx.double_spend_seen, double_spend_seen);
}


void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::output_amount_count out)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, amount, out.amount);
  WRITE_JSON_FIELD_FROM(dest, total_count, out.total_count);
  WRITE_JSON_FIELD_FROM(dest, unlocked_count, out.unlocked_count);
  WRITE_JSON_FIELD_FROM(dest, recent_count, out.recent_count);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_amount_count& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, out.amount, amount);
  READ_JSON_VALUE_BY_KEY(val, out.total_count, total_count);
  READ_JSON_VALUE_BY_KEY(val, out.unlocked_count, unlocked_count);
  READ_JSON_VALUE_BY_KEY(val, out.recent_count, recent_count);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::output_amount_and_index out)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, amount, out.amount);
  WRITE_JSON_FIELD_FROM(dest, index, out.index);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_amount_and_index& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, out.amount, amount);
  READ_JSON_VALUE_BY_KEY(val, out.index, index);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::output_key_mask_unlocked out)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, key, out.key);
  WRITE_JSON_FIELD_FROM(dest, mask, out.mask);
  WRITE_JSON_FIELD_FROM(dest, unlocked, out.unlocked);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_key_mask_unlocked& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, out.key, key);
  READ_JSON_VALUE_BY_KEY(val, out.mask, mask);
  READ_JSON_VALUE_BY_KEY(val, out.unlocked, unlocked);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::error err)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, code, err.code);
  WRITE_JSON_FIELD_FROM(dest, error_str, err.error_str);
  WRITE_JSON_FIELD_FROM(dest, message, err.message);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::error& error)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, error.code, code);
  READ_JSON_VALUE_BY_KEY(val, error.error_str, error_str);
  READ_JSON_VALUE_BY_KEY(val, error.message, message);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::BlockHeaderResponse response)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, major_version, response.major_version);
  WRITE_JSON_FIELD_FROM(dest, minor_version, response.minor_version);
  WRITE_JSON_FIELD_FROM(dest, timestamp, response.timestamp);
  WRITE_JSON_FIELD_FROM(dest, prev_id, response.prev_id);
  WRITE_JSON_FIELD_FROM(dest, nonce, response.nonce);
  WRITE_JSON_FIELD_FROM(dest, height, response.height);
  WRITE_JSON_FIELD_FROM(dest, depth, response.depth);
  WRITE_JSON_FIELD_FROM(dest, hash, response.hash);
  WRITE_JSON_FIELD_FROM(dest, difficulty, response.difficulty);
  WRITE_JSON_FIELD_FROM(dest, reward, response.reward);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::BlockHeaderResponse& response)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, response.major_version, major_version);
  READ_JSON_VALUE_BY_KEY(val, response.minor_version, minor_version);
  READ_JSON_VALUE_BY_KEY(val, response.timestamp, timestamp);
  READ_JSON_VALUE_BY_KEY(val, response.prev_id, prev_id);
  READ_JSON_VALUE_BY_KEY(val, response.nonce, nonce);
  READ_JSON_VALUE_BY_KEY(val, response.height, height);
  READ_JSON_VALUE_BY_KEY(val, response.depth, depth);
  READ_JSON_VALUE_BY_KEY(val, response.hash, hash);
  READ_JSON_VALUE_BY_KEY(val, response.difficulty, difficulty);
  READ_JSON_VALUE_BY_KEY(val, response.reward, reward);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const rct::rctSig sig)
{
  dest.StartObject();

  std::vector<rct::rct_point> masks;
  masks.reserve(sig.outPk.size());
  std::transform(sig.outPk.begin(), sig.outPk.end(), std::back_inserter(masks),
                [] (const auto & key) { return key.commit_of_amount; } );

  WRITE_JSON_FIELD_FROM(dest, type, sig.type);
  if (sig.type != rct::RCTTypeNull) {
    WRITE_JSON_FIELD_FROM(dest, encrypted, sig.ecdhInfo);
    WRITE_JSON_FIELD_FROM(dest, commitments, std::span(masks));
    WRITE_JSON_FIELD_FROM(dest, fee, sig.txnFee);
  }

  // prunable
  if (!sig.p.bulletproofs.empty() || !sig.get_pseudo_outs().empty())
  {
    dest.Key("prunable");
    dest.StartObject();

    WRITE_JSON_FIELD_FROM(dest, bulletproofs, sig.p.bulletproofs);
    WRITE_JSON_FIELD_FROM(dest, pseudo_outs, sig.get_pseudo_outs());

    dest.EndObject();
  }

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, rct::rctSig& sig)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, sig.type, type);
  if (sig.type != rct::RCTTypeNull) {
    READ_JSON_VALUE_BY_KEY(val, sig.ecdhInfo, encrypted);
    READ_JSON_VALUE_BY_KEY(val, sig.outPk, commitments);
    READ_JSON_VALUE_BY_KEY(val, sig.txnFee, fee);
  }

  // prunable
  const auto prunable = val.FindMember("prunable");
  if (prunable != val.MemberEnd())
  {
    rct::rct_pointV pseudo_outs = std::move(sig.get_pseudo_outs());

    READ_JSON_VALUE_BY_KEY(prunable->value, sig.p.bulletproofs, bulletproofs);
    READ_JSON_VALUE_BY_KEY(prunable->value, pseudo_outs, pseudo_outs);

    sig.get_pseudo_outs() = std::move(pseudo_outs);
  }
  else
  {
    sig.p.bulletproofs.clear();
    sig.get_pseudo_outs().clear();
  }
}

void fromJsonValue(const rapidjson::Value& val, rct::ct_public_key& key)
{
  key.dest = {};
  fromJsonValue(val, key.commit_of_amount);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const rct::ecdhData tuple)
{
  dest.StartObject();
  WRITE_JSON_FIELD_FROM(dest, masked_amount, tuple.masked_amount);
  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, rct::ecdhData& tuple)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, tuple.masked_amount, masked_amount);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const rct::Bulletproof p)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, V, p.V);
  WRITE_JSON_FIELD_FROM(dest, A, p.A);
  WRITE_JSON_FIELD_FROM(dest, S, p.S);
  WRITE_JSON_FIELD_FROM(dest, T1, p.T1);
  WRITE_JSON_FIELD_FROM(dest, T2, p.T2);
  WRITE_JSON_FIELD_FROM(dest, taux, p.taux);
  WRITE_JSON_FIELD_FROM(dest, mu, p.mu);
  WRITE_JSON_FIELD_FROM(dest, L, p.L);
  WRITE_JSON_FIELD_FROM(dest, R, p.R);
  WRITE_JSON_FIELD_FROM(dest, a, p.a);
  WRITE_JSON_FIELD_FROM(dest, b, p.b);
  WRITE_JSON_FIELD_FROM(dest, t, p.t);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, rct::Bulletproof& p)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, p.V, V);
  READ_JSON_VALUE_BY_KEY(val, p.A, A);
  READ_JSON_VALUE_BY_KEY(val, p.S, S);
  READ_JSON_VALUE_BY_KEY(val, p.T1, T1);
  READ_JSON_VALUE_BY_KEY(val, p.T2, T2);
  READ_JSON_VALUE_BY_KEY(val, p.taux, taux);
  READ_JSON_VALUE_BY_KEY(val, p.mu, mu);
  READ_JSON_VALUE_BY_KEY(val, p.L, L);
  READ_JSON_VALUE_BY_KEY(val, p.R, R);
  READ_JSON_VALUE_BY_KEY(val, p.a, a);
  READ_JSON_VALUE_BY_KEY(val, p.b, b);
  READ_JSON_VALUE_BY_KEY(val, p.t, t);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::DaemonInfo info)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, height, info.height);
  WRITE_JSON_FIELD_FROM(dest, target_height, info.target_height);
  WRITE_JSON_FIELD_FROM(dest, difficulty, info.difficulty);
  WRITE_JSON_FIELD_FROM(dest, target, info.target);
  WRITE_JSON_FIELD_FROM(dest, tx_count, info.tx_count);
  WRITE_JSON_FIELD_FROM(dest, tx_pool_size, info.tx_pool_size);
  WRITE_JSON_FIELD_FROM(dest, alt_blocks_count, info.alt_blocks_count);
  WRITE_JSON_FIELD_FROM(dest, outgoing_connections_count, info.outgoing_connections_count);
  WRITE_JSON_FIELD_FROM(dest, incoming_connections_count, info.incoming_connections_count);
  WRITE_JSON_FIELD_FROM(dest, white_peerlist_size, info.white_peerlist_size);
  WRITE_JSON_FIELD_FROM(dest, grey_peerlist_size, info.grey_peerlist_size);
  WRITE_JSON_FIELD_FROM(dest, mainnet, info.mainnet);
  WRITE_JSON_FIELD_FROM(dest, testnet, info.testnet);
  WRITE_JSON_FIELD_FROM(dest, nettype, info.nettype);
  WRITE_JSON_FIELD_FROM(dest, top_block_hash, info.top_block_hash);
  WRITE_JSON_FIELD_FROM(dest, cumulative_difficulty, info.cumulative_difficulty);
  WRITE_JSON_FIELD_FROM(dest, start_time, info.start_time);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::DaemonInfo& info)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, info.height, height);
  READ_JSON_VALUE_BY_KEY(val, info.target_height, target_height);
  READ_JSON_VALUE_BY_KEY(val, info.difficulty, difficulty);
  READ_JSON_VALUE_BY_KEY(val, info.target, target);
  READ_JSON_VALUE_BY_KEY(val, info.tx_count, tx_count);
  READ_JSON_VALUE_BY_KEY(val, info.tx_pool_size, tx_pool_size);
  READ_JSON_VALUE_BY_KEY(val, info.alt_blocks_count, alt_blocks_count);
  READ_JSON_VALUE_BY_KEY(val, info.outgoing_connections_count, outgoing_connections_count);
  READ_JSON_VALUE_BY_KEY(val, info.incoming_connections_count, incoming_connections_count);
  READ_JSON_VALUE_BY_KEY(val, info.white_peerlist_size, white_peerlist_size);
  READ_JSON_VALUE_BY_KEY(val, info.grey_peerlist_size, grey_peerlist_size);
  READ_JSON_VALUE_BY_KEY(val, info.mainnet, mainnet);
  READ_JSON_VALUE_BY_KEY(val, info.testnet, testnet);
  READ_JSON_VALUE_BY_KEY(val, info.nettype, nettype);
  READ_JSON_VALUE_BY_KEY(val, info.top_block_hash, top_block_hash);
  READ_JSON_VALUE_BY_KEY(val, info.cumulative_difficulty, cumulative_difficulty);
  READ_JSON_VALUE_BY_KEY(val, info.start_time, start_time);
}

void toJsonValue(rapidjson::Writer<rapidjson::StringBuffer>& dest, const cryptonote::rpc::output_distribution dist)
{
  dest.StartObject();

  WRITE_JSON_FIELD_FROM(dest, distribution, dist.data.distribution);
  WRITE_JSON_FIELD_FROM(dest, amount, dist.amount);
  WRITE_JSON_FIELD_FROM(dest, start_height, dist.data.start_height);
  WRITE_JSON_FIELD_FROM(dest, base, dist.data.base);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_distribution& dist)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  READ_JSON_VALUE_BY_KEY(val, dist.data.distribution, distribution);
  READ_JSON_VALUE_BY_KEY(val, dist.amount, amount);
  READ_JSON_VALUE_BY_KEY(val, dist.data.start_height, start_height);
  READ_JSON_VALUE_BY_KEY(val, dist.data.base, base);
}

}  // namespace json

}  // namespace cryptonote
