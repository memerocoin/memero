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

#include "cryptonote_basic.h"

namespace cryptonote
{
  void transaction_prefix::set_null()
  {
    version = 1;
    unlock_time = 0;
    vin.clear();
    vout.clear();
    extra.clear();
  }

  transaction::transaction(const transaction &t):
    transaction_prefix(t),
    ringct(t.ringct),
    unprunable_size(t.unprunable_size.load()),
    prefix_size(t.prefix_size.load())
  {
  }

  transaction &transaction::operator=(const transaction &t)
  {
    transaction_prefix::operator=(t);
    ringct = t.ringct;
    unprunable_size = t.unprunable_size.load();
    prefix_size = t.prefix_size.load();
    return *this;
  }

  transaction::transaction()
  {
    set_null();
  }

  transaction::~transaction()
  {
  }

  void transaction::set_null()
  {
    transaction_prefix::set_null();
    ringct.type = rct::RCTTypeNull;
    unprunable_size = 0;
    prefix_size = 0;
  }

  size_t transaction::get_signature_size(const txin_v& tx_in)
  {
    struct txin_signature_size_visitor : public boost::static_visitor<size_t>
    {
      size_t operator()(const txin_gen& txin) const{return 0;}
      size_t operator()(const txin_to_key& txin) const {return txin.output_relative_offsets.size();}
    };

    return boost::apply_visitor(txin_signature_size_visitor(), tx_in);
  }

  std::optional<spend_view_public_keys> maybe_safe_spend_view_public_keys(const spend_view_public_keys_unsafe x)
  {
    const auto spend_pk = maybeSafePoint(x.m_spend_public_key_unsafe);
    const auto view_pk = maybeSafePoint(x.m_view_public_key_unsafe);

    if (spend_pk && view_pk) {
      return {{*spend_pk, *view_pk}};
    }
    else {
      return {};
    }
  }
}
