/*

  Copyright 2021 fuwa

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

#include "consensus.hpp"

#include "math/ringct/pseudo_functional/bulletproofs.hpp"
#include "math/ringct/pseudo_functional/clsag.hpp"
#include "math/ringct/functional/rctOps.hpp"
#include "math/crypto/functional/group.hpp"

#include <boost/multiprecision/cpp_int.hpp>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "consensus"

namespace consensus {

  bool rule_2_ringct_output_amounts_should_not_overflow_amount_type
  (
   const rct_pointS outputs
   , const Bulletproof proof
   ) {
    return bulletproof_VERIFY(outputs, proof);
  }

  bool rule_3_ringct_should_be_balanced
  (
   const rct_pointS inputs
   , const rct_pointS outputs
   , const amount_t fee
   ) {
    return sum(inputs) == sum(outputs) + H_(crypto::int_to_scalar(fee));
  }

  bool rule_4_ringct_input_should_be_from_a_key
  (
   const crypto::hash message
   , const clsag sig
   , const output_public_dataS decoys
   , const rct_point pseudo_input_commit
   ) {
    return verify_clsag_signature(message, sig, decoys, pseudo_input_commit);
  }

  bool rule_8_ringct_input_key_images_should_be_unique(const std::span<const crypto::key_image> xs)
  {
    std::set<crypto::key_image> s(xs.begin(), xs.end());
    return s.size() == xs.size();
  }


  std::optional<Bulletproof> rule_9_range_proof_should_not_contain_invalid_data
  (
   const Bulletproof_unsafe x
   )
  {
    return maybeSafeBulletproof(x);
  }

  std::optional<clsag> rule_10_ring_signature_should_not_contain_invalid_data
  (
   const clsag_unsafe x
   )
  {
    return maybeSafeCLSAG(x);
  }

  std::optional<std::vector<crypto::ec_point>> are_points_safe
  (
   const std::span<const crypto::ec_point_unsafe> xs
   )
  {
    std::vector<std::optional<crypto::ec_point>> maybe_safe_points;

    std::transform
      (
       xs.begin()
       , xs.end()
       , std::back_inserter(maybe_safe_points)
       , crypto::maybeSafePoint
       );

    const bool all_safe_points =
      std::transform_reduce
      (
       maybe_safe_points.begin()
       , maybe_safe_points.end()
       , true
       , std::logical_and()
       , [](const std::optional<crypto::ec_point>& x) -> bool {
         return x.has_value();
       }
       );

    if (!all_safe_points) return {};

    std::vector<crypto::ec_point> safe_points;

    std::transform
      (
       maybe_safe_points.begin()
       , maybe_safe_points.end()
       , std::back_inserter(safe_points)
       , [](const auto&x) { return *x; }
       );

    return safe_points;
  }

  std::optional<std::vector<crypto::public_key>>
  rule_11_tx_output_public_keys_should_be_safe_points
  (
   const std::span<const crypto::ec_point_unsafe> xs
   ) {
    const auto maybe_safe_points = are_points_safe(xs);
    if (!maybe_safe_points) {
      return {};
    } else {
      std::vector<crypto::public_key> keys;
      std::transform
        (
         maybe_safe_points->begin()
         , maybe_safe_points->end()
         , std::back_inserter(keys)
         , crypto::p2pk
         );

      return keys;
    }
  }


  std::optional<cryptonote::txout_to_key>
  rule_12_tx_output_target_should_be_output_public_key(const cryptonote::txout_target_v x) {
    if (x.type() == typeid(cryptonote::txout_to_key)) {
      return boost::get<cryptonote::txout_to_key>(x);
    } else {
      return {};
    }
  }

  std::optional<std::vector<cryptonote::txout_to_key>>
  are_tx_output_targets_valid(const std::span<const cryptonote::txout_target_v> xs) {

    std::vector<std::optional<cryptonote::txout_to_key>> maybe_valid;

    std::transform
      (
       xs.begin()
       , xs.end()
       , std::back_inserter(maybe_valid)
       , rule_12_tx_output_target_should_be_output_public_key
       );

    const bool all_valid =
      std::transform_reduce
      (
       maybe_valid.begin()
       , maybe_valid.end()
       , true
       , std::logical_and()
       , [](const auto& x) -> bool {
         return x.has_value();
       }
       );

    if (!all_valid) return {};

    std::vector<cryptonote::txout_to_key> valid_targets;
    std::transform
      (
       maybe_valid.begin()
       , maybe_valid.end()
       , std::back_inserter(valid_targets)
       , [](const auto& x) { return *x; }
       );

    return valid_targets;
  }

  std::optional<cryptonote::txin_from_key>
  rule_15_ringct_input_type_should_be_from_key(const cryptonote::txin_v x) {
    if (x.type() == typeid(cryptonote::txin_from_key)) {
      return boost::get<cryptonote::txin_from_key>(x);
    } else {
      return {};
    }
  }

  std::optional<std::vector<cryptonote::txin_from_key>>
  are_ringct_input_types_valid(const std::span<const cryptonote::txin_v> xs) {

    std::vector<std::optional<cryptonote::txin_from_key>> maybe_from_keys;

    std::transform
      (
       xs.begin()
       , xs.end()
       , std::back_inserter(maybe_from_keys)
       , rule_15_ringct_input_type_should_be_from_key
       );

    const bool all_from_keys =
      std::transform_reduce
      (
       maybe_from_keys.begin()
       , maybe_from_keys.end()
       , true
       , std::logical_and()
       , [](const auto& x) -> bool {
         return x.has_value();
       }
       );

    if (!all_from_keys) return {};

    std::vector<cryptonote::txin_from_key> from_keys;

    std::transform
      (
       maybe_from_keys.begin()
       , maybe_from_keys.end()
       , std::back_inserter(from_keys)
       , [](const auto& x) { return *x; }
       );

    return from_keys;
  }

  std::optional<rct::Bulletproof_unsafe>
  rule_17_ringct_should_contain_only_one_range_proof
  (
   const std::span<const rct::Bulletproof_unsafe> proofs
   )
  {
    if (proofs.size() == 1) {
      return proofs.front();
    } else {
      return {};
    }
  }

  bool rule_21_ringct_should_have_at_least_two_outputs
  (
   const std::span<const cryptonote::tx_out> xs
   )
  {
    return xs.size() >= 2;
  }

  std::optional<cryptonote::txin_v> rule_22_coinbase_tx_should_have_only_one_input
  (
   const std::span<const cryptonote::txin_v> xs
   )
  {
    if (xs.size() == 1) {
      return xs.front();
    } else {
      return {};
    };
  }

  std::optional<cryptonote::txin_gen> rule_23_coinbase_tx_input_type_should_be_gen
  (
   const cryptonote::txin_v x
   )
  {
    if (x.type() == typeid(cryptonote::txin_gen)) {
      return boost::get<cryptonote::txin_gen>(x);
    } else {
      return {};
    };
  }

  std::optional<uint64_t> rule_24_coinbase_output_amount_sum_should_not_overflow_amount_t
  (
   const std::span<const uint64_t> xs
   )
  {
    using namespace boost::multiprecision;
    constexpr uint128_t max64bit = std::numeric_limits<uint64_t>::max();

    const uint128_t sum = std::transform_reduce
      (
       xs.begin()
       , xs.end()
       , uint128_t(0)
       , std::plus<uint128_t>() 
       , [](const uint64_t x) -> uint128_t { return uint128_t(x); }
       );

    if (sum <= max64bit) {
      return uint64_t(sum);
    } else {
      return {};
    };
  }

  std::optional<cryptonote::txin_v> rule_25_ringct_should_have_at_least_one_input
  (
   const std::span<const cryptonote::txin_v> xs
   )
  {
    if (!xs.empty()) {
      return xs.front();
    } else {
      return {};
    };
  }

}
