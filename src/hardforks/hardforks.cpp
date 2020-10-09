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

#include "hardforks.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "blockchain.hardforks"

const hardfork_t mainnet_hard_forks[] = {
  { 17, 0, 0, 1600576524 },
};
const size_t num_mainnet_hard_forks = sizeof(mainnet_hard_forks) / sizeof(mainnet_hard_forks[0]);

const hardfork_t testnet_hard_forks[] = {
  { 17, 0, 0, 1600576524 },
};
const size_t num_testnet_hard_forks = sizeof(testnet_hard_forks) / sizeof(testnet_hard_forks[0]);

const hardfork_t stagenet_hard_forks[] = {
  // version 1 from the start of the blockchain
  { 1, 1, 0, 1341378000 },

  // versions 2-7 in rapid succession from March 13th, 2018
  { 2, 32000, 0, 1521000000 },
  { 3, 33000, 0, 1521120000 },
  { 4, 34000, 0, 1521240000 },
  { 5, 35000, 0, 1521360000 },
  { 6, 36000, 0, 1521480000 },
  { 7, 37000, 0, 1521600000 },
  { 8, 176456, 0, 1537821770 },
  { 9, 177176, 0, 1537821771 },
  { 10, 269000, 0, 1550153694 },
  { 11, 269720, 0, 1550225678 },
  { 12, 454721, 0, 1571419280 },
  { 13, 675405, 0, 1598180817 },
  { 14, 676125, 0, 1598180818 },
};
const size_t num_stagenet_hard_forks = sizeof(stagenet_hard_forks) / sizeof(stagenet_hard_forks[0]);
