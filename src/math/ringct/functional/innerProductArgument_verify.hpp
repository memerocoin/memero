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
#include "innerProductArgument_gen.hpp"

namespace rct
{
  bool verify_inner_product_argument
  (
   const InnerProductArgument ipa
   , const crypto::ec_scalar challenge
   , const scalarS a
   , const scalarS b
   );

  bool verify_recursive_inner_product_argument
  (
   const RecursiveInnerProductArgument ipa
   , const crypto::ec_scalar challenge
   );
}
