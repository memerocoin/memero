// Copyright (c) 2017-2020, The Monero Project
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

#include "rpc_client.h"

#include "wallet_errors.h"

#include "tools/epee/include/net/http_abstract_invoke.h"
#include "network/rpc/core_rpc_server_commands_defs.h"
#include "cryptonote/basic/cryptonote_format_utils.h"

#include "wallet/logic/state/gamma_picker.hpp"
#include "wallet/logic/type/transfer.hpp"

#include <boost/format.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/range/adaptor/transformed.hpp>


#define RETURN_ON_RPC_RESPONSE_ERROR(r, error, res, method) \
  do { \
    LOG_ERROR_AND_RETURN_UNLESS(error.code == 0, error.message, error.message); \
    LOG_ERROR_AND_RETURN_UNLESS(r, std::string("Failed to connect to daemon"), "Failed to connect to daemon"); \
    /* empty string -> not connection */ \
    LOG_ERROR_AND_RETURN_UNLESS(!res.status.empty(), res.status, "No connection to daemon"); \
    LOG_ERROR_AND_RETURN_UNLESS(res.status != CORE_RPC_STATUS_BUSY, res.status, "Daemon busy"); \
    LOG_ERROR_AND_RETURN_UNLESS(res.status == CORE_RPC_STATUS_OK, res.status, "Error calling " + std::string(method) + " daemon RPC"); \
  } while(0)

using namespace epee;
using namespace cryptonote;
using namespace wallet::logic::type::transfer;

namespace tools
{

constexpr std::chrono::seconds rpc_timeout = config::lol::rpc_timeout;

RPC_Client::RPC_Client(epee::net_utils::http::abstract_http_client &http_client, std::recursive_mutex &mutex)
  : m_http_client(http_client)
  , m_daemon_rpc_mutex(mutex)
  , m_offline(false)
{
}

std::optional<std::string> RPC_Client::get_height(uint64_t &height) const
{
  if (m_offline)
    return std::optional<std::string>("offline");

  cryptonote::COMMAND_RPC_GET_INFO::request req_t = AUTO_VAL_INIT(req_t);
  cryptonote::COMMAND_RPC_GET_INFO::response resp_t = AUTO_VAL_INIT(resp_t);

  {
    const std::lock_guard<std::recursive_mutex> lock{m_daemon_rpc_mutex};
    bool r = epee::net_utils::invoke_http_json_rpc("/json_rpc", "get_info", req_t, resp_t, m_http_client, rpc_timeout);
    RETURN_ON_RPC_RESPONSE_ERROR(r, epee::json_rpc::error{}, resp_t, "get_info");
  }

  height = resp_t.height;

  return {};
}

std::optional<std::string> RPC_Client::get_target_height(uint64_t &height) const
{
  if (m_offline)
    return std::optional<std::string>("offline");

  cryptonote::COMMAND_RPC_GET_INFO::request req_t = AUTO_VAL_INIT(req_t);
  cryptonote::COMMAND_RPC_GET_INFO::response resp_t = AUTO_VAL_INIT(resp_t);

  {
    const std::lock_guard<std::recursive_mutex> lock{m_daemon_rpc_mutex};
    bool r = epee::net_utils::invoke_http_json_rpc("/json_rpc", "get_info", req_t, resp_t, m_http_client, rpc_timeout);
    RETURN_ON_RPC_RESPONSE_ERROR(r, epee::json_rpc::error{}, resp_t, "get_info");
  }

  height = resp_t.target_height;

  return {};
}

bool RPC_Client::get_rct_distribution(uint64_t &start_height, std::vector<uint64_t> &distribution) const
{
  cryptonote::COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::request req = AUTO_VAL_INIT(req);
  cryptonote::COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::response res = AUTO_VAL_INIT(res);
  req.amounts.push_back(0);
  req.from_height = 0;
  req.cumulative = true;

  try
  {
    const std::lock_guard<std::recursive_mutex> lock{m_daemon_rpc_mutex};
    bool r = epee::net_utils::invoke_http_json_rpc("/json_rpc", "get_output_distribution", req, res, m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, {}, res, "/get_output_distribution");
  }
  catch(...)
  {
    return false;
  }
  if (res.distributions.size() != 1)
  {
    LOG_WARNING("Failed to request output distribution: not the expected single result");
    return false;
  }
  if (res.distributions[0].amount != 0)
  {
    LOG_WARNING("Failed to request output distribution: results are not for amount 0");
    return false;
  }
  start_height = res.distributions[0].data.start_height;
  distribution = std::move(res.distributions[0].data.distribution);

  return true;
}

void RPC_Client::get_tx_outputs
(
   const std::vector<size_t> selected_transfers
 , const wallet::logic::type::wallet::transfer_container_span m_transfers
 , const size_t fake_outputs_count
 , std::vector<std::vector<wallet::logic::type::get_tx_outputs_entry>> &outs
 , std::vector<uint64_t> &rct_offsets
 ) const
{
  LOG_PRINT_L2("fake_outputs_count: " << fake_outputs_count);
  outs.clear();

  if (fake_outputs_count > 0)
  {
    // check whether we're shortly after the fork
    uint64_t height;
    std::optional<std::string> result = get_height(height);
    THROW_WALLET_EXCEPTION_IF(result, error::wallet_internal_error, "Failed to get height");

    // if we have at least one rct out, get the distribution, or fall back to the previous system
    uint64_t rct_start_height;
    uint64_t max_rct_index = 0;
    for (size_t idx: selected_transfers)
      if (m_transfers[idx].is_rct())
      {
        max_rct_index = std::max(max_rct_index, m_transfers[idx].m_global_output_index);
      }
    const bool has_rct_distribution = !rct_offsets.empty() ||
      get_rct_distribution(rct_start_height, rct_offsets);

    THROW_WALLET_EXCEPTION_IF(!has_rct_distribution, error::wallet_internal_error, "no rct distribution");
    if (has_rct_distribution)
    {
      // check we're clear enough of rct start, to avoid corner cases below
      THROW_WALLET_EXCEPTION_IF(rct_offsets.size() <= CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE,
          error::get_output_distribution, "Not enough rct outputs");
      THROW_WALLET_EXCEPTION_IF(rct_offsets.back() <= max_rct_index,
          error::get_output_distribution, "Daemon reports suspicious number of rct outputs");
    }

    // we ask for more, to have spares if some outputs are still locked
    size_t base_requested_outputs_count = (size_t)((fake_outputs_count + 1) * 1.5 + 1);
    LOG_PRINT_L2("base_requested_outputs_count: " << base_requested_outputs_count);

    // generate output indices to request
    cryptonote::COMMAND_RPC_GET_OUTPUTS::request req = AUTO_VAL_INIT(req);
    cryptonote::COMMAND_RPC_GET_OUTPUTS::response daemon_resp = AUTO_VAL_INIT(daemon_resp);

    std::unique_ptr<wallet::logic::state::gamma_picker> gamma;
    if (has_rct_distribution)
      gamma = std::make_unique<wallet::logic::state::gamma_picker>(rct_offsets);

    size_t num_selected_transfers = 0;
    for(size_t idx: selected_transfers)
    {
      ++num_selected_transfers;
      const transfer_details &td = m_transfers[idx];
      const uint64_t amount = 0;
      std::unordered_set<uint64_t> seen_indices;
      // request more for rct in base recent (locked) coinbases are picked, since they're locked for longer
      size_t requested_outputs_count = base_requested_outputs_count + (td.is_rct() ? CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE : 0);
      size_t start = req.outputs.size();
      uint64_t num_outs = 0, num_recent_outs = 0;

      {
        // the base offset of the first rct output in the first unlocked block (or the one to be if there's none)
        num_outs = rct_offsets[rct_offsets.size() - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE];
        LOG_PRINT_L1("" << num_outs << " unlocked rct outputs");
        THROW_WALLET_EXCEPTION_IF(num_outs == 0, error::wallet_internal_error,
            "histogram reports no unlocked rct outputs, not even ours");
      }

      // how many fake outs to draw on a pre-fork distribution
      // how many fake outs to draw otherwise

      size_t recent_outputs_count = 0;
      LOG_PRINT_L1("Fake output makeup: " << requested_outputs_count << " requested: " << recent_outputs_count << " recent, " <<
          (requested_outputs_count - recent_outputs_count) << " full-chain");

      uint64_t num_found = 0;

      if (num_outs <= requested_outputs_count)
      {
        for (uint64_t i = 0; i < num_outs; i++)
          req.outputs.push_back({amount, i});
        // duplicate to make up shortfall: this will be caught after the RPC call,
        // so we can also output the amounts for which we can't reach the required
        // mixin after checking the actual unlockedness
        for (uint64_t i = num_outs; i < requested_outputs_count; ++i)
          req.outputs.push_back({amount, num_outs - 1});
      }
      else
      {
        // start with real one
        if (num_found == 0)
        {
          num_found = 1;
          seen_indices.emplace(td.m_global_output_index);
          req.outputs.push_back({amount, td.m_global_output_index});
          LOG_PRINT_L1("Selecting real output: " << td.m_global_output_index << " for " << print_money(amount));
        }

        std::unordered_map<const char*, std::set<uint64_t>> picks;

        // while we still need more mixins
        uint64_t num_usable_outs = num_outs;
        bool allow_blackballed = false;
        LOG_DEBUG("Starting gamma picking with " << num_outs << ", num_usable_outs " << num_usable_outs
            << ", requested_outputs_count " << requested_outputs_count);
        while (num_found < requested_outputs_count)
        {
          // if we've gone through every possible output, we've gotten all we can
          if (seen_indices.size() == num_usable_outs)
          {
            // there is a first pass which rejects blackballed outputs, then a second pass
            // which allows them if we don't have enough non blackballed outputs to reach
            // the required amount of outputs (since consensus does not care about blackballed
            // outputs, we still need to reach the minimum ring size)
            if (allow_blackballed)
              break;
            LOG_INFO("Not enough output not marked as spent, we'll allow outputs marked as spent");
            allow_blackballed = true;
            num_usable_outs = num_outs;
          }

          // get a random output index from the DB.  If we've already seen it,
          // return to the top of the loop and try again, otherwise add it to the
          // list of output indices we've seen.

          uint64_t i;
          const char *type = "";
          if (amount == 0 && has_rct_distribution)
          {
            THROW_WALLET_EXCEPTION_IF(!gamma, error::wallet_internal_error, "No gamma picker");
            {
              do i = gamma->pick(); while (i >= num_outs);
              type = "gamma";
            }
          }
          else if (num_found - 1 < recent_outputs_count) // -1 to account for the real one we seeded with
          {
            // triangular distribution over [a,b) with a=0, mode c=b=up_index_limit
            uint64_t r = crypto::rand<uint64_t>() % ((uint64_t)1 << 53);
            double frac = std::sqrt((double)r / ((uint64_t)1 << 53));
            i = (uint64_t)(frac*num_recent_outs) + num_outs - num_recent_outs;
            // just in case rounding up to 1 occurs after calc
            if (i == num_outs)
              --i;
            type = "recent";
          }
          else
          {
            // triangular distribution over [a,b) with a=0, mode c=b=up_index_limit
            uint64_t r = crypto::rand<uint64_t>() % ((uint64_t)1 << 53);
            double frac = std::sqrt((double)r / ((uint64_t)1 << 53));
            i = (uint64_t)(frac*num_outs);
            // just in case rounding up to 1 occurs after calc
            if (i == num_outs)
              --i;
            type = "triangular";
          }

          if (seen_indices.count(i))
            continue;
          seen_indices.emplace(i);

          picks[type].insert(i);
          req.outputs.push_back({amount, i});
          ++num_found;
          LOG_DEBUG("picked " << i << ", " << num_found << " now picked");
        }

        for (const auto &pick: picks)
          LOG_DEBUG("picking " << pick.first << " outputs: " <<
              boost::join(pick.second | boost::adaptors::transformed([](uint64_t out){return std::to_string(out);}), " "));

        // if we had enough unusable outputs, we might fall off here and still
        // have too few outputs, so we stuff with one to keep counts good, and
        // we'll error out later
        while (num_found < requested_outputs_count)
        {
          req.outputs.push_back({amount, 0});
          ++num_found;
        }
      }

      // sort the subsection, to ensure the daemon doesn't know which output is ours
      std::sort(std::next(req.outputs.begin(), start), req.outputs.end(),
          [](const get_outputs_out &a, const get_outputs_out &b) { return a.index < b.index; });
    }

    constexpr auto _is_debug = false;
    if (_is_debug)
    {
      std::map<uint64_t, std::set<uint64_t>> outs;
      for (const auto &i: req.outputs)
        outs[i.amount].insert(i.index);
      for (const auto &o: outs)
        LOG_DEBUG("asking for outputs with amount " << print_money(o.first) << ": " <<
            boost::join(o.second | boost::adaptors::transformed([](uint64_t out){return std::to_string(out);}), " "));
    }

    // get the keys for those
    req.get_txid = false;

    {
      const std::lock_guard<std::recursive_mutex> lock{m_daemon_rpc_mutex};

      bool r = epee::net_utils::invoke_http_json("/get_tx_outputs", req, daemon_resp, m_http_client, rpc_timeout);
      THROW_ON_RPC_RESPONSE_ERROR(r, {}, daemon_resp, "get_tx_outputs", error::get_tx_outputs_error, (daemon_resp.status));
      THROW_WALLET_EXCEPTION_IF(daemon_resp.outs.size() != req.outputs.size(), error::wallet_internal_error,
        "daemon returned wrong response for get_tx_outputs.bin, wrong amounts count = " +
        std::to_string(daemon_resp.outs.size()) + ", expected " +  std::to_string(req.outputs.size()));
    }

    std::unordered_map<uint64_t, uint64_t> scanty_outs;
    size_t base = 0;
    outs.reserve(num_selected_transfers);
    for(size_t idx: selected_transfers)
    {
      const transfer_details &td = m_transfers[idx];
      size_t requested_outputs_count = base_requested_outputs_count + (td.is_rct() ? CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE : 0);
      outs.push_back(std::vector<wallet::logic::type::get_tx_outputs_entry>());
      outs.back().reserve(fake_outputs_count + 1);

      THROW_WALLET_EXCEPTION_IF(!td.is_rct(), error::wallet_internal_error,
                                "td is not rct");

      const rct::rct_point mask = rct::commit(td.m_mask, td.amount());

      // make sure the real outputs we asked for are really included, along
      // with the correct key and mask: this guards against an active attack
      // where the node sends dummy data for all outputs, and we then send
      // the real one, which the node can then tell from the fake outputs,
      // as it has different data than the dummy data it had sent earlier
      bool real_out_found = false;

      std::vector<COMMAND_RPC_GET_OUTPUTS_BIN::outkey> resp_outputs;
      std::transform
        (
         daemon_resp.outs.begin()
         , daemon_resp.outs.end()
         , std::back_inserter(resp_outputs)
         , rpc::parse_tx_output_result
         );
      
      for (size_t n = 0; n < requested_outputs_count; ++n)
      {
        size_t i = base + n;
        if (req.outputs[i].index == td.m_global_output_index)
          if
            (
             resp_outputs[i].key
             == boost::get<txout_to_key>(td.m_tx.vout[td.m_internal_output_index].target).shared_secret_derived_public_key
             )
            if (resp_outputs[i].mask == mask)
              real_out_found = true;
      }
      THROW_WALLET_EXCEPTION_IF(!real_out_found, error::wallet_internal_error,
          "Daemon response did not include the requested real output");

      // pick real out first (it will be sorted when done)
      outs.back().push_back
        (
         std::make_tuple(td.m_global_output_index, boost::get<txout_to_key>(td.m_tx.vout[td.m_internal_output_index].target).shared_secret_derived_public_key, mask)
         );

      // then pick others in random order till we reach the required number
      // since we use an equiprobable pick here, we don't upset the triangular distribution
      std::vector<size_t> order;
      order.resize(requested_outputs_count);
      for (size_t n = 0; n < order.size(); ++n)
        order[n] = n;
      std::shuffle(order.begin(), order.end(), crypto::random_device{});

      LOG_PRINT_L2("Looking for " << (fake_outputs_count+1) << " outputs of size " << print_money(td.is_rct() ? 0 : td.amount()));
      for (size_t o = 0; o < requested_outputs_count && outs.back().size() < fake_outputs_count + 1; ++o)
      {
        size_t i = base + order[o];
        LOG_PRINT_L2("Index " << i << "/" << requested_outputs_count << ": idx " << req.outputs[i].index << " (real " << td.m_global_output_index << "), unlocked " << resp_outputs[i].unlocked << ", key " << resp_outputs[i].key);
        tx_add_fake_output(outs, req.outputs[i].index, resp_outputs[i].key, resp_outputs[i].mask, td.m_global_output_index, resp_outputs[i].unlocked);
      }
      if (outs.back().size() < fake_outputs_count + 1)
      {
        scanty_outs[td.is_rct() ? 0 : td.amount()] = outs.back().size();
      }
      else
      {
        // sort the subsection, so any spares are reset in order
        std::sort(outs.back().begin(), outs.back().end(), [](const wallet::logic::type::get_tx_outputs_entry &a, const wallet::logic::type::get_tx_outputs_entry &b) { return std::get<0>(a) < std::get<0>(b); });
      }
      base += requested_outputs_count;
    }
    THROW_WALLET_EXCEPTION_IF(!scanty_outs.empty(), error::not_enough_outs_to_mix, scanty_outs, fake_outputs_count);
  }
  else
  {
    for (size_t idx: selected_transfers)
    {
      const transfer_details &td = m_transfers[idx];
      std::vector<wallet::logic::type::get_tx_outputs_entry> v;

      THROW_WALLET_EXCEPTION_IF(!td.is_rct(), error::wallet_internal_error,
                                "td is not rct");

      const rct::rct_point mask = rct::commit(td.m_mask, td.amount());
      v.push_back(std::make_tuple(td.m_global_output_index, td.get_public_key(), mask));
      outs.push_back(v);
    }
  }
}

bool RPC_Client::tx_add_fake_output
(
 std::vector<std::vector<wallet::logic::type::get_tx_outputs_entry>> &outs
 , uint64_t global_index
 , const crypto::public_key& output_public_key
 , const rct::rct_point& mask
 , uint64_t real_index
 , bool unlocked
 ) const
{
  if (!unlocked) // don't add locked outs
    return false;
  if (global_index == real_index) // don't re-add real one
    return false;
  auto item = std::make_tuple(global_index, output_public_key, mask);
  LOG_ERROR_AND_RETURN_UNLESS(!outs.empty(), false, "internal error: outs is empty");
  if (std::find(outs.back().begin(), outs.back().end(), item) != outs.back().end()) // don't add duplicates
    return false;
  // check the keys are valid
  if (!crypto::is_safe_point(rct::pk2rct_p(output_public_key)))
  {
    LOG_WARNING("Key " << output_public_key << " at index " << global_index << " is not in the main subgroup");
    return false;
  }
  if (!crypto::is_safe_point(mask))
  {
    LOG_WARNING("Commitment " << mask << " at index " << global_index << " is not in the main subgroup");
    return false;
  }
  outs.back().push_back(item);
  return true;
}

namespace rpc {
  using namespace cryptonote;

  COMMAND_RPC_GET_OUTPUTS_BIN::outkey parse_tx_output_result(COMMAND_RPC_GET_OUTPUTS::outkey x) {
    crypto::public_key key;
    const auto key_data = parse_crypto_data(x.key);
    if (key_data) {
      const auto maybe_key = crypto::maybeSafePoint(crypto::d2p(*key_data));
      if (maybe_key) {
        key = crypto::p2pk(*maybe_key);
      }
    }

    rct::rct_point mask;
    const auto mask_data = parse_crypto_data(x.mask);
    if (mask_data) {
      const auto maybe_mask = crypto::maybeSafePoint(crypto::d2p(*mask_data));
      if (maybe_mask) {
        mask = rct::p2rct_p(*maybe_mask);
      }
    }


    return COMMAND_RPC_GET_OUTPUTS_BIN::outkey
      {
        key
        , mask
        , x.unlocked
        , x.height
        , {}
      };
  }
}

}
