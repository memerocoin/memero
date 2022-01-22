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

#pragma once

#include "rctTypes.hpp"

namespace rct
{

  std::pair<crypto::ec_point, crypto::ec_point>
  init_inner_product_argument
  (
   const pointS G
   , const pointS H
   , const scalarS a
   , const scalarS b
   , const crypto::ec_point u
   );

  std::tuple
  <
    const pointV
    , const pointV
    , const scalarV
    , const scalarV
    >
  reduce_inner_product_argument
  (
   const pointS G
   , const pointS H
   , const scalarS a
   , const scalarS b
   , const crypto::ec_scalar challenge
   );

}
