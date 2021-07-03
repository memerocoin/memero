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

#include "daemon_messages.h"

#include "tools/serialization/json_object.h"

namespace cryptonote
{

namespace rpc
{
void GetHeight::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{}

void GetHeight::Request::fromJson(const rapidjson::Value& val)
{
}

void GetHeight::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, height, height);
}

void GetHeight::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, height, height);
}


void GetBlocksFast::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, block_ids, block_ids);
  WRITE_JSON_FIELD_FROM(dest, start_height, start_height);
  WRITE_JSON_FIELD_FROM(dest, prune, prune);
}

void GetBlocksFast::Request::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, block_ids, block_ids);
  READ_JSON_VALUE_BY_KEY(val, start_height, start_height);
  READ_JSON_VALUE_BY_KEY(val, prune, prune);
}

void GetBlocksFast::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, blocks, blocks);
  WRITE_JSON_FIELD_FROM(dest, start_height, start_height);
  WRITE_JSON_FIELD_FROM(dest, current_height, current_height);
  WRITE_JSON_FIELD_FROM(dest, output_indices, output_indices);
}

void GetBlocksFast::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, blocks, blocks);
  READ_JSON_VALUE_BY_KEY(val, start_height, start_height);
  READ_JSON_VALUE_BY_KEY(val, current_height, current_height);
  READ_JSON_VALUE_BY_KEY(val, output_indices, output_indices);
}


void GetHashesFast::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, known_hashes, known_hashes);
  WRITE_JSON_FIELD_FROM(dest, start_height, start_height);
}

void GetHashesFast::Request::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, known_hashes, known_hashes);
  READ_JSON_VALUE_BY_KEY(val, start_height, start_height);
}

void GetHashesFast::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, hashes, hashes);
  WRITE_JSON_FIELD_FROM(dest, start_height, start_height);
  WRITE_JSON_FIELD_FROM(dest, current_height, current_height);
}

void GetHashesFast::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, hashes, hashes);
  READ_JSON_VALUE_BY_KEY(val, start_height, start_height);
  READ_JSON_VALUE_BY_KEY(val, current_height, current_height);
}


void GetTransactions::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, tx_hashes, tx_hashes);
}

void GetTransactions::Request::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, tx_hashes, tx_hashes);
}

void GetTransactions::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, txs, txs);
  WRITE_JSON_FIELD_FROM(dest, missed_hashes, missed_hashes);
}

void GetTransactions::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, txs, txs);
  READ_JSON_VALUE_BY_KEY(val, missed_hashes, missed_hashes);
}


void KeyImagesSpent::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, key_images, key_images);
}

void KeyImagesSpent::Request::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, key_images, key_images);
}

void KeyImagesSpent::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, spent_status, spent_status);
}

void KeyImagesSpent::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, spent_status, spent_status);
}


void GetTxGlobalOutputIndices::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, tx_hash, tx_hash);
}

void GetTxGlobalOutputIndices::Request::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, tx_hash, tx_hash);
}

void GetTxGlobalOutputIndices::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, output_indices, output_indices);
}

void GetTxGlobalOutputIndices::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, output_indices, output_indices);
}

void SendRawTx::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, tx, tx);
  WRITE_JSON_FIELD_FROM(dest, relay, relay);
}

void SendRawTx::Request::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, tx, tx);
  READ_JSON_VALUE_BY_KEY(val, relay, relay);
}

void SendRawTx::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, relayed, relayed);
}


void SendRawTx::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, relayed, relayed);
}

void SendRawTxHex::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, tx_as_hex, tx_as_hex);
  WRITE_JSON_FIELD_FROM(dest, relay, relay);
}

void SendRawTxHex::Request::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, tx_as_hex, tx_as_hex);
  READ_JSON_VALUE_BY_KEY(val, relay, relay);
}

void StartMining::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, miner_address, miner_address);
  WRITE_JSON_FIELD_FROM(dest, threads_count, threads_count);
}

void StartMining::Request::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, miner_address, miner_address);
  READ_JSON_VALUE_BY_KEY(val, threads_count, threads_count);
}

void StartMining::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{}

void StartMining::Response::fromJson(const rapidjson::Value& val)
{
}


void StopMining::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{}

void StopMining::Request::fromJson(const rapidjson::Value& val)
{
}

void StopMining::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{}

void StopMining::Response::fromJson(const rapidjson::Value& val)
{
}


void MiningStatus::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{}

void MiningStatus::Request::fromJson(const rapidjson::Value& val)
{
}

void MiningStatus::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, active, active);
  WRITE_JSON_FIELD_FROM(dest, speed, speed);
  WRITE_JSON_FIELD_FROM(dest, threads_count, threads_count);
  WRITE_JSON_FIELD_FROM(dest, address, address);
}

void MiningStatus::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, active, active);
  READ_JSON_VALUE_BY_KEY(val, speed, speed);
  READ_JSON_VALUE_BY_KEY(val, threads_count, threads_count);
  READ_JSON_VALUE_BY_KEY(val, address, address);
}


void GetInfo::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{}

void GetInfo::Request::fromJson(const rapidjson::Value& val)
{
}

void GetInfo::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, info, info);
}

void GetInfo::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, info, info);
}


void SaveBC::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{}

void SaveBC::Request::fromJson(const rapidjson::Value& val)
{
}

void SaveBC::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{}

void SaveBC::Response::fromJson(const rapidjson::Value& val)
{
}


void GetBlockHash::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, height, height);
}

void GetBlockHash::Request::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, height, height);
}

void GetBlockHash::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, hash, hash);
}

void GetBlockHash::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, hash, hash);
}


void GetLastBlockHeader::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{}

void GetLastBlockHeader::Request::fromJson(const rapidjson::Value& val)
{
}

void GetLastBlockHeader::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, header, header);
}

void GetLastBlockHeader::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, header, header);
}


void GetBlockHeaderByHash::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, hash, hash);
}

void GetBlockHeaderByHash::Request::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, hash, hash);
}

void GetBlockHeaderByHash::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, header, header);
}

void GetBlockHeaderByHash::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, header, header);
}


void GetBlockHeaderByHeight::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, height, height);
}

void GetBlockHeaderByHeight::Request::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, height, height);
}

void GetBlockHeaderByHeight::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, header, header);
}

void GetBlockHeaderByHeight::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, header, header);
}


void GetBlockHeadersByHeight::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, heights, heights);
}

void GetBlockHeadersByHeight::Request::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, heights, heights);
}

void GetBlockHeadersByHeight::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, headers, headers);
}

void GetBlockHeadersByHeight::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, headers, headers);
}


void GetPeerList::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{}

void GetPeerList::Request::fromJson(const rapidjson::Value& val)
{
}

void GetPeerList::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, white_list, white_list);
  WRITE_JSON_FIELD_FROM(dest, gray_list, gray_list);
}

void GetPeerList::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, white_list, white_list);
  READ_JSON_VALUE_BY_KEY(val, gray_list, gray_list);
}


void SetLogLevel::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, level, level);
}

void SetLogLevel::Request::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, level, level);
}

void SetLogLevel::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{}

void SetLogLevel::Response::fromJson(const rapidjson::Value& val)
{
}


void GetTransactionPool::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{}

void GetTransactionPool::Request::fromJson(const rapidjson::Value& val)
{
}

void GetTransactionPool::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, transactions, transactions);
  WRITE_JSON_FIELD_FROM(dest, key_images, key_images);
}

void GetTransactionPool::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, transactions, transactions);
  READ_JSON_VALUE_BY_KEY(val, key_images, key_images);
}

void GetOutputHistogram::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, amounts, amounts);
  WRITE_JSON_FIELD_FROM(dest, min_count, min_count);
  WRITE_JSON_FIELD_FROM(dest, max_count, max_count);
  WRITE_JSON_FIELD_FROM(dest, unlocked, unlocked);
  WRITE_JSON_FIELD_FROM(dest, recent_cutoff, recent_cutoff);
}

void GetOutputHistogram::Request::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, amounts, amounts);
  READ_JSON_VALUE_BY_KEY(val, min_count, min_count);
  READ_JSON_VALUE_BY_KEY(val, max_count, max_count);
  READ_JSON_VALUE_BY_KEY(val, unlocked, unlocked);
  READ_JSON_VALUE_BY_KEY(val, recent_cutoff, recent_cutoff);
}

void GetOutputHistogram::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, histogram, histogram);
}

void GetOutputHistogram::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, histogram, histogram);
}


void GetOutputKeys::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, outputs, outputs);
}

void GetOutputKeys::Request::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, outputs, outputs);
}

void GetOutputKeys::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, keys, keys);
}

void GetOutputKeys::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, keys, keys);
}

void GetOutputDistribution::Request::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, amounts, amounts);
  WRITE_JSON_FIELD_FROM(dest, from_height, from_height);
  WRITE_JSON_FIELD_FROM(dest, to_height, to_height);
  WRITE_JSON_FIELD_FROM(dest, cumulative, cumulative);
}

void GetOutputDistribution::Request::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, amounts, amounts);
  READ_JSON_VALUE_BY_KEY(val, from_height, from_height);
  READ_JSON_VALUE_BY_KEY(val, to_height, to_height);
  READ_JSON_VALUE_BY_KEY(val, cumulative, cumulative);
}

void GetOutputDistribution::Response::doToJson(rapidjson::Writer<rapidjson::StringBuffer>& dest) const
{
  WRITE_JSON_FIELD_FROM(dest, status, status);
  WRITE_JSON_FIELD_FROM(dest, distributions, distributions);
}

void GetOutputDistribution::Response::fromJson(const rapidjson::Value& val)
{
  READ_JSON_VALUE_BY_KEY(val, status, status);
  READ_JSON_VALUE_BY_KEY(val, distributions, distributions);
}

}  // namespace rpc

}  // namespace cryptonote
