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


#include "tx_common.hpp"

#include "tools/epee/include/logging.hpp"
#include "consensus/consensus.hpp"

namespace cryptonote {

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

  const auto maybe_targets = consensus::are_tx_output_targets_valid(output_targets);

  if (!maybe_targets) {
    LOG_ERROR("wrong variant type in output targets");
    return false;
  }

  const auto targets = *maybe_targets;

  std::vector<crypto::ec_point_unsafe> output_public_keys;
  std::transform
    (
     targets.begin()
     , targets.end()
     , std::back_inserter(output_public_keys)
     , [](const auto& x) {
       return x.output_public_key;
     }
     );

  const bool valid_output_public_keys =
    consensus::rule_11_tx_output_public_keys_should_be_safe_points(output_public_keys).has_value();

  return valid_output_public_keys;
}

bool check_ringct_points(const transaction& tx) {
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
    consensus::rule_13_tx_output_commits_should_be_safe_points(output_commits).has_value();

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
    consensus::rule_14_tx_pseudo_input_commits_should_be_safe_points(pseudo_input_commits).has_value();


  return valid_output_commits && valid_pseudo_input_commits;
}

}
