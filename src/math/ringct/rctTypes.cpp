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

#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/int-util.h"

#include "config/cryptonote.hpp"

using namespace std;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

namespace rct {

    //Various Conversions

    key key::operator+(const key& y) const
    {
      return p2rct(ec_point::operator+(y));
    }

    //uint long long to 32 byte key
    scalar int_to_scalar(const amount_t in) {
        scalar x;
        sc_0(x.data);
        memcpy_swap64le(x.data, &in, 1);
        return x;
    }

    //32 byte key to uint long long
    // if the key holds a value > 2^64
    // then the value in the first 8 bytes is returned
    amount_t scalar_to_int(const scalar & in) {
        amount_t vali = 0;
        int j = 0;
        for (j = 7; j >= 0; j--) {
            vali = (amount_t)(vali * 256 + (unsigned char)in.data[j]);
        }
        return vali;
    }

    size_t n_bulletproof_amounts(const Bulletproof &proof)
    {
        LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() >= 6, 0, "Invalid bulletproof L size");
        LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() == proof.R.size(), 0, "Mismatched bulletproof L/R size");
        static const size_t extra_bits = 4;
        static_assert((1 << extra_bits) == constant::BULLETPROOF_MAX_OUTPUTS, "log2(constant::BULLETPROOF_MAX_OUTPUTS) is out of date");
        LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() <= 6 + extra_bits, 0, "Invalid bulletproof L size");
        LOG_ERROR_AND_RETURN_UNLESS(proof.V.size() <= (1u<<(proof.L.size()-6)), 0, "Invalid bulletproof V/L");
        LOG_ERROR_AND_RETURN_UNLESS(proof.V.size() * 2 > (1u<<(proof.L.size()-6)), 0, "Invalid bulletproof V/L");
        LOG_ERROR_AND_RETURN_UNLESS(proof.V.size() > 0, 0, "Empty bulletproof");
        return proof.V.size();
    }

    size_t n_bulletproof_amounts(const std::vector<Bulletproof> &proofs)
    {
        size_t n = 0;
        for (const Bulletproof &proof: proofs)
        {
            size_t n2 = n_bulletproof_amounts(proof);
            LOG_ERROR_AND_RETURN_UNLESS(n2 < std::numeric_limits<uint32_t>::max() - n, 0, "Invalid number of bulletproofs");
            if (n2 == 0)
                return 0;
            n += n2;
        }
        return n;
    }

    size_t n_bulletproof_max_amounts(const Bulletproof &proof)
    {
        LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() >= 6, 0, "Invalid bulletproof L size");
        LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() == proof.R.size(), 0, "Mismatched bulletproof L/R size");
        static const size_t extra_bits = 4;
        static_assert((1 << extra_bits) == constant::BULLETPROOF_MAX_OUTPUTS, "log2(constant::BULLETPROOF_MAX_OUTPUTS) is out of date");
        LOG_ERROR_AND_RETURN_UNLESS(proof.L.size() <= 6 + extra_bits, 0, "Invalid bulletproof L size");
        return 1 << (proof.L.size() - 6);
    }

    size_t n_bulletproof_max_amounts(const std::vector<Bulletproof> &proofs)
    {
        size_t n = 0;
        for (const Bulletproof &proof: proofs)
        {
            size_t n2 = n_bulletproof_max_amounts(proof);
            LOG_ERROR_AND_RETURN_UNLESS(n2 < std::numeric_limits<uint32_t>::max() - n, 0, "Invalid number of bulletproofs");
            if (n2 == 0)
                return 0;
            n += n2;
        }
        return n;
    }

}
