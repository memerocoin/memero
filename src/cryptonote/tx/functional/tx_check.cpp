// Copyright (c) 2019-2020, The Monero Project
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

#include "tx_check.h"

#include "cryptonote/basic/functional/format_utils.hpp"

#include "consensus/consensus.hpp"


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "verify"

namespace cryptonote
{

bool rct_tx_sanity_check(const cryptonote::string_blob &tx_blob, uint64_t rct_outs_available)
{
  const auto maybeTx = maybe_tx_from_blob(tx_blob);
  if (!maybeTx)
  {
    LOG_ERROR("Failed to parse transaction");
    return false;
  }

  const auto tx = *maybeTx;

  if (cryptonote::is_coinbase(tx))
  {
    LOG_ERROR("Transaction is coinbase");
    return false;
  }
  std::set<uint64_t> rct_indices;
  size_t n_indices = 0;

  for (const auto &txin : tx.vin)
  {
    if (txin.type() != typeid(cryptonote::txin_from_key))
      continue;
    const cryptonote::txin_from_key &in_to_key = boost::get<cryptonote::txin_from_key>(txin);
    if (in_to_key.amount != 0)
      continue;
    const std::vector<uint64_t> absolute = cryptonote::relative_output_offsets_to_absolute(in_to_key.output_relative_offsets);
    for (uint64_t offset: absolute)
      rct_indices.insert(offset);
    n_indices += in_to_key.output_relative_offsets.size();
  }

  return rct_tx_sanity_check(rct_indices, n_indices, rct_outs_available);
}

bool rct_tx_sanity_check(const std::set<uint64_t> &rct_indices, size_t n_indices, uint64_t rct_outs_available)
{
  if (n_indices <= 10)
  {
    LOG_DEBUG("n_indices is only " << n_indices << ", not checking");
    return true;
  }

  if (rct_outs_available < 10000)
    return true;

  if (rct_indices.size() < n_indices * 8 / 10)
  {
    LOG_ERROR("amount of unique indices is too low (amount of rct indices is " << rct_indices.size() << ", out of total " << n_indices << "indices.");
    return false;
  }

  std::vector<uint64_t> offsets(rct_indices.begin(), rct_indices.end());
  uint64_t median = epee::misc_utils::median(offsets);
  if (median < rct_outs_available * 6 / 10)
  {
    LOG_ERROR("median offset index is too low (median is " << median << " out of total " << rct_outs_available << "offsets). Transactions should contain a higher fraction of recent outputs.");
    return false;
  }

  return true;
}

bool check_tx_output_points(const transaction& tx) {

  std::vector<cryptonote::txout_target_v> output_targets;
  std::transform
    (
     tx.vout.begin()
     , tx.vout.end()
     , std::back_inserter(output_targets)
     , [](const auto& x) {
       return x.target;
     }
     );

  if (!consensus::are_tx_output_targets_valid(output_targets)) {
    LOG_ERROR("wrong variant type in output targets");
    return false;
  }

  std::vector<crypto::ec_point_unsafe> output_public_keys;
  std::transform
    (
     tx.vout.begin()
     , tx.vout.end()
     , std::back_inserter(output_public_keys)
     , [](const auto& x) {
       return boost::get<txout_to_key>(x.target).output_public_key;
     }
     );

  const bool valid_output_public_keys =
    consensus::rule_11_tx_output_public_keys_should_be_safe_points(output_public_keys);

  // double check points in ringct
  std::vector<crypto::ec_point_unsafe> output_commits;
  std::transform
    (
     tx.ringct.output_commits.begin()
     , tx.ringct.output_commits.end()
     , std::back_inserter(output_commits)
     , [](const auto& x) {
       return x.commit;
     }
     );

  const bool valid_output_commits =
    consensus::rule_13_tx_output_commits_should_be_safe_points(output_commits);

  std::vector<crypto::ec_point_unsafe> pseudo_input_commits;
  std::transform
    (
     tx.ringct.p.pseudo_input_commits.begin()
     , tx.ringct.p.pseudo_input_commits.end()
     , std::back_inserter(pseudo_input_commits)
     , [](const auto& x) {
       return x;
     }
     );

  const bool valid_pseudo_input_commits =
    consensus::rule_14_tx_pseudo_input_commits_should_be_safe_points(pseudo_input_commits);


  return valid_output_public_keys && valid_output_commits && valid_pseudo_input_commits;
}


bool check_tx_input_points(const transaction& tx)
{
  return consensus::are_ringct_input_types_valid(tx.vin);

}

}
