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

#include "wallet_errors.h"

#include "network/rpc/core_rpc_server_error_codes.h"

namespace tools
{
namespace error
{
  std::string unexpected_txin_type::to_string() const
  {
    std::ostringstream ss;
    cryptonote::transaction tx = m_tx;
    ss << wallet_internal_error::to_string() << ", tx:\n" << cryptonote::obj_to_json_str(tx);
    return ss.str();
  }

  std::string acc_outs_lookup_error::to_string() const
  {
    std::ostringstream ss;
    cryptonote::transaction tx = m_tx;
    ss << refresh_error::to_string() << ", tx: " << cryptonote::obj_to_json_str(tx);
    return ss.str();
  }

  std::string not_enough_unlocked_money::to_string() const
  {
    std::ostringstream ss;
    ss << transfer_error::to_string() <<
      ", available = " << cryptonote::print_money(m_available) <<
      ", tx_amount = " << cryptonote::print_money(m_tx_amount);
    return ss.str();
  }

  std::string not_enough_money::to_string() const
  {
    std::ostringstream ss;
    ss << transfer_error::to_string() <<
      ", available = " << cryptonote::print_money(m_available) <<
      ", tx_amount = " << cryptonote::print_money(m_tx_amount);
    return ss.str();
  }

  std::string tx_not_possible::to_string() const
  {
    std::ostringstream ss;
    ss << transfer_error::to_string() <<
      ", available = " << cryptonote::print_money(m_available) <<
      ", tx_amount = " << cryptonote::print_money(m_tx_amount) <<
      ", fee = " << cryptonote::print_money(m_fee);
    return ss.str();
  }

  std::string not_enough_outs_to_mix::to_string() const
  {
    std::ostringstream ss;
    ss << transfer_error::to_string() << ", ring size = " << (m_mixin_count + 1) << ", scanty_outs:";
    for (const auto& out: m_scanty_outs)
      {
        ss << '\n' << cryptonote::print_money(out.first) << " - " << out.second;
      }
    return ss.str();
  }

  std::string tx_not_constructed::to_string() const
  {
    std::ostringstream ss;
    ss << transfer_error::to_string();
    ss << "\nSources:";
    for (size_t i = 0; i < m_sources.size(); ++i)
      {
        const cryptonote::tx_source_entry& src = m_sources[i];
        ss << "\n  source " << i << ":";
        ss << "\n    amount: " << cryptonote::print_money(src.amount);
        // It's not good, if logs will contain such much data
        //ss << "\n    real_output: " << src.real_output;
        //ss << "\n    real_output_in_tx_index: " << src.real_output_in_tx_index;
        //ss << "\n    real_out_tx_key: " << epee::string_tools::pod_to_hex(src.real_out_tx_key);
        //ss << "\n    outputs:";
        //for (size_t j = 0; j < src.outputs.size(); ++j)
        //{
        //  const cryptonote::tx_source_entry::output_entry& out = src.outputs[j];
        //  ss << "\n      " << j << ": " << out.first << ", " << epee::string_tools::pod_to_hex(out.second);
        //}
      }

    ss << "\nDestinations:";
    for (size_t i = 0; i < m_destinations.size(); ++i)
      {
        const cryptonote::tx_destination_entry& dst = m_destinations[i];
        ss << "\n  " << i << ": " << cryptonote::get_account_address_as_str(m_nettype, dst.is_subaddress, dst.addr) << " " <<
          cryptonote::print_money(dst.amount);
      }

    ss << "\nunlock_height: " << m_unlock_height;

    return ss.str();
  }

  std::string tx_rejected::to_string() const
  {
    std::ostringstream ss;
    ss << transfer_error::to_string() << ", status = " << m_status << ", tx:\n";
    cryptonote::transaction tx = m_tx;
    ss << cryptonote::obj_to_json_str(tx);
    if (!m_reason.empty())
      {
        ss << " (" << m_reason << ")";
      }
    return ss.str();
  }

  std::string tx_sum_overflow::to_string() const
  {
    std::ostringstream ss;
    ss << transfer_error::to_string() <<
      ", fee = " << cryptonote::print_money(m_fee) <<
      ", destinations:";
    for (const auto& dst : m_destinations)
      {
        ss << '\n' << cryptonote::print_money(dst.amount) << " -> " << cryptonote::get_account_address_as_str(m_nettype, dst.is_subaddress, dst.addr);
      }
    return ss.str();
  }

  std::string tx_too_big::to_string() const
  {
    std::ostringstream ss;
    ss << transfer_error::to_string() <<
      ", tx_weight_limit = " << m_tx_weight_limit <<
      ", tx weight = " << m_tx_weight;
    if (m_tx_valid)
      {
        cryptonote::transaction tx = m_tx;
        ss << ", tx:\n" << cryptonote::obj_to_json_str(tx);
      }
    return ss.str();
  }

  std::string wallet_rpc_error::to_string() const
  {
    std::ostringstream ss;
    ss << wallet_logic_error::to_string() << ", request = " << m_request;
    return ss.str();
  }
} // error


  //----------------------------------------------------------------------------------------------------
  void throw_on_rpc_response_error(bool r, const epee::json_rpc::error &error, const std::string &status, const char *method)
  {
    THROW_WALLET_EXCEPTION_IF(error.code, tools::error::wallet_coded_rpc_error, method, error.code,
                              get_rpc_server_error_message(error.code));
    THROW_WALLET_EXCEPTION_IF(!r, tools::error::no_connection_to_daemon, method);
    // empty string -> not connection
    THROW_WALLET_EXCEPTION_IF(status.empty(), tools::error::no_connection_to_daemon, method);

    THROW_WALLET_EXCEPTION_IF(status == CORE_RPC_STATUS_BUSY, tools::error::daemon_busy, method);
  }

} //tools
