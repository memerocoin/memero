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

#pragma once

#include "cryptonote/basic/type/string_blob_type.hpp"
#include "cryptonote/protocol/connection_context.h"

#include "tools/epee/include/net/levin_protocol_handler_async.h"

#include <boost/asio.hpp>


namespace cryptonote
{
namespace levin
{
  using connections = epee::levin::async_protocol_handler_config;

  namespace detail
  {
    using p2p_context = nodetool::p2p_connection_context_t<cryptonote::cryptonote_connection_context>;

    struct zone
    {
      explicit zone(std::shared_ptr<connections> p2p, bool is_public)
        : p2p(std::move(p2p)),
          connection_count(0)
      {
      }

      const std::shared_ptr<connections> p2p;
      std::atomic<std::size_t> connection_count; //!< Only update in strand, can be read at any time
    };
  } // detail


  class notify
  {
    std::shared_ptr<detail::zone> zone_;

  public:
    notify() = default;

    //! Construct an instance with available notification `zones`.
    explicit notify(std::shared_ptr<connections> p2p, bool is_public);

    notify(const notify&) = delete;
    notify(notify&&) = default;

    notify& operator=(const notify&) = delete;
    notify& operator=(notify&&) = default;

    bool send_txs(const std::vector<string_blob> txs, const boost::uuids::uuid& source);
  };
} // levin
} // net
