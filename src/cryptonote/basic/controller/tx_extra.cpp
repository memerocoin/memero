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

#include "tx_extra.hpp"

#include "tools/epee/include/string_tools.h"
#include "tools/serialization/string.h" // don't remove, or face core dump

#include "math/ringct/pseudo_functional/rctSigs.hpp"

#include "cryptonote/basic/functional/subaddress.hpp"

#include <boost/algorithm/string.hpp>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "cn"

using namespace constant;

namespace cryptonote
{
  //---------------------------------------------------------------
  std::vector<uint8_t> add_tx_output_keys_to_extra
  (const std::vector<uint8_t>& tx_extra_in, const std::span<const crypto::public_key> output_pub_keys)
  {
    std::vector<uint8_t> tx_extra = tx_extra_in;
    // convert to variant
    std::vector<crypto::ec_point_unsafe> output_pub_keys_unsafe;

    std::transform
      (
       output_pub_keys.begin()
       , output_pub_keys.end()
       , std::back_inserter(output_pub_keys_unsafe)
       , [](const auto&x) { return x; }
       );

    tx_extra_field field = tx_extra_tx_output_public_keys{ output_pub_keys_unsafe };
    // serialize
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    bool r = ::do_serialize(ar, field);

    LOG_WITH_LEVEL_1_AND_RETURN_UNLESS(r, tx_extra_in, "failed to serialize tx extra tx output pub keys");

    // append
    std::string tx_extra_str = oss.str();
    std::copy(tx_extra_str.begin(), tx_extra_str.end(), std::back_inserter(tx_extra));
    return tx_extra;
  }

}
