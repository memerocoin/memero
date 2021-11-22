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

namespace consensus {

  bool rule_2_tx_output_amounts_should_not_overflow_amount_type
  (
   const rct_pointS outputs
   , const Bulletproof proof
   ) {
    return bulletproof_VERIFY(outputs, proof);
  }

  bool rule_3_tx_should_be_balanced
  (
   const rct_pointS inputs
   , const rct_pointS outputs
   , const amount_t fee
   ) {
    return sum(inputs) == sum(outputs) + H_(crypto::int_to_scalar(fee));
  }

  bool rule_4_tx_input_should_be_from_a_ring
  (
   const crypto::hash message
   , const clsag sig
   , const output_public_dataS decoys
   , const rct_point pseudo_input_commit
   ) {
    return verify_clsag_signature(message, sig, decoys, pseudo_input_commit);
  }

  bool rule_8_tx_input_key_images_should_be_unique(const std::span<const crypto::key_image> xs)
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

}
