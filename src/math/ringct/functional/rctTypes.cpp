// Copyright (c) 2016, Monero Research Labs
//
// Author: Shen Noether <shen.noether@gmx.com>
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

#include "rctTypes.hpp"
#include "rctOps.hpp"


namespace rct {

  const rct::inv8V to_inv8V(const pointS xs) {
    inv8V ys;
    std::transform
      (
       xs.begin()
       , xs.end()
       , std::back_inserter(ys)
       , [](const auto& x) { return to_inv8(x); }
       );

    return ys;
  }


  std::optional<LR_V> zipLR(const pointV L, const pointV R) {
    if (L.size() != R.size()) {
      return {};
    }

    std::vector<std::pair<crypto::ec_point, crypto::ec_point>> LR;

    std::transform
      (
       L.begin()
       , L.end()
       , R.begin()
       , std::back_inserter(LR)
       , [](const auto& x, const auto& y) { return std::make_pair(x, y); }
       );

    return LR;
  }

  std::pair<pointV, pointV>
  splitLR(const std::span<const std::pair<crypto::ec_point, crypto::ec_point>> LR) {
    pointV L;
    pointV R;

    std::transform
      (
       LR.begin()
       , LR.end()
       , std::back_inserter(L)
       , [](const auto& x) { return x.first; }
       );

    std::transform
      (
       LR.begin()
       , LR.end()
       , std::back_inserter(R)
       , [](const auto& x) { return x.second; }
       );

    return {L, R};
  }

}
