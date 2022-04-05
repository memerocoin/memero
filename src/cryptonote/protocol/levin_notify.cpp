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

#include "math/crypto/controller/random.hpp"

#include <random>



namespace cryptonote
{
namespace levin
{
  namespace
  {
    /* A custom duration is used for the poisson distribution because of the
       variance. If 5 seconds is given to `std::poisson_distribution`, 95% of
       the values fall between 1-9s in 1s increments (not granular enough). If
       5000 milliseconds is given, 95% of the values fall between 4859ms-5141ms
       in 1ms increments (not enough time variance). Providing 20 quarter
       seconds yields 95% of the values between 3s-7.25s in 1/4s increments. */
    using fluff_stepsize = std::chrono::duration<std::chrono::milliseconds::rep, std::ratio<1, 20>>;
    constexpr auto fluff_average_in = constant::CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE;

    /*! Bitcoin Core is using 1/2 average seconds for outgoing connections
        compared to incoming. The thinking is that the user controls outgoing
        connections (Dandelion++ makes similar assumptions in its stem
        algorithm). The randomization yields 95% values between 1s-4s in
	1/4s increments. */
    constexpr const fluff_stepsize fluff_average_out{fluff_stepsize{fluff_average_in} / 2};

    class random_poisson
    {
      std::poisson_distribution<fluff_stepsize::rep> dist;
    public:
      explicit random_poisson(fluff_stepsize average)
        : dist(average.count() < 0 ? 0 : average.count())
      {}

      fluff_stepsize operator()()
      {
        crypto::random_device rand{};
        return fluff_stepsize{dist(rand)};
      }
    };

    /*! Select a randomized duration from 0 to `range`. The precision will be to
        the systems `steady_clock`. As an example, supplying 3 seconds to this
        function will select a duration from [0, 3] seconds, and the increments
        for the selection will be determined by the `steady_clock` precision
        (typically nanoseconds).

        \return A randomized duration from 0 to `range`. */
    std::chrono::steady_clock::duration random_duration(std::chrono::steady_clock::duration range)
    {
      using rep = std::chrono::steady_clock::rep;
      return std::chrono::steady_clock::duration{crypto::rand_range(rep(0), range.count())};
    }

    std::string make_tx_payload(const std::span<const string_blob> txs)
    {
      NOTIFY_NEW_TRANSACTIONS::request request{};
      request.txs = std::vector<string_blob>{txs.begin(), txs.end()};

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
      p2p.for_connection(destination, [&blob](detail::p2p_context& context) {
        on_levin_traffic(context, true, true, false, blob.size(), NOTIFY_NEW_TRANSACTIONS::ID);
        return true;
      });
      return p2p.notify(NOTIFY_NEW_TRANSACTIONS::ID, epee::string_tools::string_to_blob(blob), destination);
    }

  } // anonymous

  notify::notify(boost::asio::io_service& service, std::shared_ptr<connections> p2p, const bool is_public)
    : zone_(std::make_shared<detail::zone>(service, std::move(p2p), is_public))
  {
    if (!zone_->p2p)
      throw std::logic_error{"cryptonote::levin::notify cannot have nullptr p2p argument"};
  }

  notify::~notify() noexcept
  {}

  bool notify::send_txs(const std::vector<string_blob> txs, const boost::uuids::uuid& source)
  {
    if (txs.empty())
      return true;

    if (!zone_)
      return false;

    zone_->p2p->foreach_connection
      ([&] (detail::p2p_context& context)
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
