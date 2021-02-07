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

#include "levin_notify.h"

#include <boost/asio/steady_timer.hpp>
#include <boost/system/system_error.hpp>
#include <chrono>
#include <deque>
#include <stdexcept>
#include <utility>

#include "common/expect.h"
#include "common/varint.h"
#include "config/cryptonote.hpp"
#include "crypto/random.h"
#include "cryptonote/basic/connection_context.h"
#include "cryptonote/protocol/cryptonote_protocol_defs.h"
#include "network/type/dandelionpp.h"
#include "p2p/net_node.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net.p2p.tx"

namespace cryptonote
{
namespace levin
{
  namespace
  {
    constexpr std::size_t connection_id_reserve_size = 100;

    /* A custom duration is used for the poisson distribution because of the
       variance. If 5 seconds is given to `std::poisson_distribution`, 95% of
       the values fall between 1-9s in 1s increments (not granular enough). If
       5000 milliseconds is given, 95% of the values fall between 4859ms-5141ms
       in 1ms increments (not enough time variance). Providing 20 quarter
       seconds yields 95% of the values between 3s-7.25s in 1/4s increments. */
    using fluff_stepsize = std::chrono::duration<std::chrono::milliseconds::rep, std::ratio<1, 4>>;
    constexpr const std::chrono::seconds fluff_average_in{CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE};

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

    std::string make_tx_payload(std::vector<blobdata>&& txs)
    {
      NOTIFY_NEW_TRANSACTIONS::request request{};
      request.txs = std::move(txs);

      std::string fullBlob;
      if (!epee::serialization::store_t_to_binary(request, fullBlob))
        throw std::runtime_error{"Failed to serialize to epee binary format"};

      return fullBlob;
    }

    bool make_payload_send_txs(connections& p2p, std::vector<blobdata>&& txs, const boost::uuids::uuid& destination)
    {
      const cryptonote::blobdata blob = make_tx_payload(std::move(txs));
      p2p.for_connection(destination, [&blob](detail::p2p_context& context) {
        on_levin_traffic(context, true, true, false, blob.size(), NOTIFY_NEW_TRANSACTIONS::ID);
        return true;
      });
      return p2p.notify(NOTIFY_NEW_TRANSACTIONS::ID, epee::strspan<std::uint8_t>(blob), destination);
    }

    /* The current design uses `asio::strand`s. The documentation isn't as clear
       as it should be - a `strand` has an internal `mutex` and `bool`. The
       `mutex` synchronizes thread access and the `bool` is set when a thread is
       executing something "in the strand". Therefore, if a callback has lots of
       work to do in a `strand`, asio can switch to some other task instead of
       blocking 1+ threads to wait for the original thread to complete the task
       (as is the case when client code has a `mutex` inside the callback). The
       downside is that asio _always_ allocates for the callback, even if it can
       be immediately executed. So if all work in a strand is minimal, a lock
       may be better.

       This code uses a strand per "zone" and a strand per "channel in a zone".
       `dispatch` is used heavily, which means "execute immediately in _this_
       thread if the strand is not in use, otherwise queue the callback to be
       executed immediately after the strand completes its current task".
       `post` is used where deferred execution to an `asio::io_service::run`
       thread is preferred.

       The strand per "zone" is useful because the levin
       `foreach_connection` is blocked with a mutex anyway. So this primarily
       helps with reducing blocking of a thread attempting a "flood"
       notification. Updating/merging the outgoing connections in the
       Dandelion++ map is also somewhat expensive.

       The strand per "channel" may need a re-visit. The most "expensive" code
       is figuring out the noise/notification to send. If levin code is
       optimized further, it might be better to just use standard locks per
       channel. */
  } // anonymous

  namespace detail
  {
    struct zone
    {
      explicit zone(boost::asio::io_service& io_service, std::shared_ptr<connections> p2p, bool is_public)
        : p2p(std::move(p2p)),
          next_epoch(io_service),
          flush_txs(io_service),
          strand(io_service),
          flush_time(std::chrono::steady_clock::time_point::max()),
          connection_count(0)
      {
      }

      const std::shared_ptr<connections> p2p;
      boost::asio::steady_timer next_epoch;
      boost::asio::steady_timer flush_txs;
      boost::asio::io_service::strand strand;
      std::chrono::steady_clock::time_point flush_time; //!< Next expected Dandelion++ fluff flush
      std::atomic<std::size_t> connection_count; //!< Only update in strand, can be read at any time
    };
  } // detail

  namespace
  {
    //! Sends txs on connections with expired timers, and queues callback for next timer expiration (if any).
    struct fluff_flush
    {
      std::shared_ptr<detail::zone> zone_;
      std::chrono::steady_clock::time_point flush_time_;

      static void queue(std::shared_ptr<detail::zone> zone, const std::chrono::steady_clock::time_point flush_time)
      {
        assert(zone != nullptr);
        assert(zone->strand.running_in_this_thread());

        detail::zone& this_zone = *zone;
        this_zone.flush_time = flush_time;
        this_zone.flush_txs.expires_at(flush_time);
        this_zone.flush_txs.async_wait(this_zone.strand.wrap(fluff_flush{std::move(zone), flush_time}));
      }

      void operator()(const boost::system::error_code error)
      {
        if (!zone_ || !zone_->p2p)
          return;

        assert(zone_->strand.running_in_this_thread());

        const bool timer_error = bool(error);
        if (timer_error)
        {
          if (error != boost::system::errc::operation_canceled)
            throw boost::system::system_error{error, "fluff_flush timer failed"};

          // new timer canceled this one set in future
          if (zone_->flush_time < flush_time_)
            return;
        }

        const auto now = std::chrono::steady_clock::now();
        auto next_flush = std::chrono::steady_clock::time_point::max();
        std::vector<std::pair<std::vector<blobdata>, boost::uuids::uuid>> connections{};
        zone_->p2p->foreach_connection([timer_error, now, &next_flush, &connections] (detail::p2p_context& context)
        {
          if (!context.fluff_txs.empty())
          {
            if (context.flush_time <= now || timer_error) // flush on canceled timer
            {
              context.flush_time = std::chrono::steady_clock::time_point::max();
              connections.emplace_back(std::move(context.fluff_txs), context.m_connection_id);
              context.fluff_txs.clear();
            }
            else // not flushing yet
              next_flush = std::min(next_flush, context.flush_time);
          }
          else // nothing to flush
            context.flush_time = std::chrono::steady_clock::time_point::max();
          return true;
        });

        for (auto& connection : connections)
        {
          std::sort(connection.first.begin(), connection.first.end()); // don't leak receive order
          make_payload_send_txs(*zone_->p2p, std::move(connection.first), connection.second);
        }

        if (next_flush != std::chrono::steady_clock::time_point::max())
          fluff_flush::queue(std::move(zone_), next_flush);
        else
          zone_->flush_time = next_flush; // signal that no timer is set
      }
    };

    /*! The "fluff" portion of the Dandelion++ algorithm. Every tx is queued
        per-connection and flushed with a randomized poisson timer. This
        implementation only has one system timer per-zone, and instead tracks
        the lowest flush time. */
    struct fluff_notify
    {
      std::shared_ptr<detail::zone> zone_;
      std::vector<blobdata> txs_;
      boost::uuids::uuid source_;

      void operator()()
      {
        if (!zone_ || !zone_->p2p || txs_.empty())
          return;

        assert(zone_->strand.running_in_this_thread());

        const auto now = std::chrono::steady_clock::now();
        auto next_flush = std::chrono::steady_clock::time_point::max();

        random_poisson in_duration(fluff_average_in);
        random_poisson out_duration(fluff_average_out);

        bool available = false;
        zone_->p2p->foreach_connection([this, now, &in_duration, &out_duration, &next_flush, &available] (detail::p2p_context& context)
        {
          if (context.handshake_complete() && this->source_ != context.m_connection_id)
          {
            available = true;
            if (context.fluff_txs.empty())
              context.flush_time = now + (context.m_is_income ? in_duration() : out_duration());

            next_flush = std::min(next_flush, context.flush_time);
            context.fluff_txs.reserve(context.fluff_txs.size() + this->txs_.size());
            for (const blobdata& tx : this->txs_)
              context.fluff_txs.push_back(tx); // must copy instead of move (multiple conns)
          }
          return true;
        });

        if (!available)
          MWARNING("Unable to send transaction(s), no available connections");

        if (next_flush < zone_->flush_time)
          fluff_flush::queue(std::move(zone_), next_flush);
      }
    };

    //! Prepares connections for new channel/dandelionpp epoch and sets timer for next epoch
    struct start_epoch
    {
      // Variables allow for Dandelion++ extension
      std::shared_ptr<detail::zone> zone_;
      std::chrono::seconds min_epoch_;
      std::chrono::seconds epoch_range_;
      std::size_t count_;

      //! \pre Should not be invoked within any strand to prevent blocking.
      void operator()(const boost::system::error_code error = {})
      {
        if (!zone_ || !zone_->p2p)
          return;

        if (error && error != boost::system::errc::operation_canceled)
          throw boost::system::system_error{error, "start_epoch timer failed"};

        const auto start = std::chrono::steady_clock::now();

        detail::zone& alias = *zone_;
        alias.next_epoch.expires_at(start + min_epoch_ + random_duration(epoch_range_));
        alias.next_epoch.async_wait(start_epoch{std::move(*this)});
      }
    };
  } // anonymous

  notify::notify(boost::asio::io_service& service, std::shared_ptr<connections> p2p, const bool is_public)
    : zone_(std::make_shared<detail::zone>(service, std::move(p2p), is_public))
  {
    if (!zone_->p2p)
      throw std::logic_error{"cryptonote::levin::notify cannot have nullptr p2p argument"};
  }

  notify::~notify() noexcept
  {}

  notify::status notify::get_status() const noexcept
  {
    if (!zone_)
      return {};

    return {};
  }

  void notify::run_epoch()
  {
    if (!zone_)
      return;
    zone_->next_epoch.cancel();
  }

  void notify::run_fluff()
  {
    if (!zone_)
      return;
    zone_->flush_txs.cancel();
  }

  bool notify::send_txs(std::vector<blobdata> txs, const boost::uuids::uuid& source)
  {
    if (txs.empty())
      return true;

    if (!zone_)
      return false;

    {
      zone_->strand.dispatch(fluff_notify{zone_, std::move(txs), source});
    }

    return true;
  }
} // levin
} // net
