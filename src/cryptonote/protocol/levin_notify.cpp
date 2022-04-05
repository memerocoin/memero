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


#include "network/p2p/net_node.h" // circular dependency

#include <algorithm>
#include <random>

namespace cryptonote
{
namespace levin
{
  namespace
  {
    using p2p_context =
      nodetool::p2p_connection_context_t
      <cryptonote::cryptonote_connection_context>;

    std::string make_tx_payload(const std::span<const string_blob> txs)
    {
      NOTIFY_NEW_TRANSACTIONS::request request{};

      auto txs_shuffle = std::vector<string_blob>{txs.begin(), txs.end()};
      std::shuffle(txs_shuffle.begin(), txs_shuffle.end(), std::random_device());

      request.txs = txs_shuffle;

      std::string fullBlob;
      if (!epee::serialization::store_t_to_binary(request, fullBlob))
        throw std::runtime_error{"Failed to serialize to epee binary format"};

      return fullBlob;
    }

    bool make_payload_send_txs
    (
     connections& p2p
     , const std::span<const string_blob> txs
     , const boost::uuids::uuid& destination
     )
    {
      const cryptonote::string_blob blob = make_tx_payload(txs);

      p2p.for_connection(destination, [&blob](p2p_context& context) {
        on_levin_traffic(context, true, true, false, blob.size(), NOTIFY_NEW_TRANSACTIONS::ID);
        return true;
      });
      return p2p.notify(NOTIFY_NEW_TRANSACTIONS::ID, epee::string_tools::string_to_blob(blob), destination);
    }

  } // anonymous

  notify::notify(std::shared_ptr<connections> p2p, const bool is_public)
    : zone_(std::make_shared<detail::zone>(std::move(p2p), is_public))
  {
    if (!zone_->p2p)
      throw std::logic_error{"cryptonote::levin::notify cannot have nullptr p2p argument"};
  }

  bool notify::send_txs(const std::vector<string_blob> txs, const boost::uuids::uuid& source)
  {
    if (txs.empty())
      return true;

    if (!zone_)
      return false;

    zone_->p2p->foreach_connection
      ([&] (p2p_context& context)
      {
        if
          (
           context.handshake_complete()
           && source != context.m_connection_id
           )
          {
            make_payload_send_txs
              (*zone_->p2p, txs, context.m_connection_id);
          }
        return true;
      });

    return true;
  }

} // levin
} // net
