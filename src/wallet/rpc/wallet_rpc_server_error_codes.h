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

#pragma  once


constexpr int64_t WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR               =  -1;
constexpr int64_t WALLET_RPC_ERROR_CODE_WRONG_ADDRESS               =  -2;
constexpr int64_t WALLET_RPC_ERROR_CODE_DAEMON_IS_BUSY              =  -3;
constexpr int64_t WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR      =  -4;
constexpr int64_t WALLET_RPC_ERROR_CODE_TRANSFER_TYPE               =  -6;
constexpr int64_t WALLET_RPC_ERROR_CODE_DENIED                      =  -7;
constexpr int64_t WALLET_RPC_ERROR_CODE_WRONG_TXID                  =  -8;
constexpr int64_t WALLET_RPC_ERROR_CODE_WRONG_SIGNATURE             =  -9;
constexpr int64_t WALLET_RPC_ERROR_CODE_WRONG_KEY_IMAGE             = -10;
constexpr int64_t WALLET_RPC_ERROR_CODE_WRONG_URI                   = -11;
constexpr int64_t WALLET_RPC_ERROR_CODE_WRONG_INDEX                 = -12;
constexpr int64_t WALLET_RPC_ERROR_CODE_NOT_OPEN                    = -13;
constexpr int64_t WALLET_RPC_ERROR_CODE_ACCOUNT_INDEX_OUT_OF_BOUNDS = -14;
constexpr int64_t WALLET_RPC_ERROR_CODE_ADDRESS_INDEX_OUT_OF_BOUNDS = -15;
constexpr int64_t WALLET_RPC_ERROR_CODE_TX_NOT_POSSIBLE             = -16;
constexpr int64_t WALLET_RPC_ERROR_CODE_NOT_ENOUGH_MONEY            = -17;
constexpr int64_t WALLET_RPC_ERROR_CODE_TX_TOO_LARGE                = -18;
constexpr int64_t WALLET_RPC_ERROR_CODE_NOT_ENOUGH_OUTS_TO_MIX      = -19;
constexpr int64_t WALLET_RPC_ERROR_CODE_ZERO_DESTINATION            = -20;
constexpr int64_t WALLET_RPC_ERROR_CODE_WALLET_ALREADY_EXISTS       = -21;
constexpr int64_t WALLET_RPC_ERROR_CODE_INVALID_PASSWORD            = -22;
constexpr int64_t WALLET_RPC_ERROR_CODE_NO_WALLET_DIR               = -23;
constexpr int64_t WALLET_RPC_ERROR_CODE_NO_TXKEY                    = -24;
constexpr int64_t WALLET_RPC_ERROR_CODE_WRONG_KEY                   = -25;
constexpr int64_t WALLET_RPC_ERROR_CODE_BAD_HEX                     = -26;
constexpr int64_t WALLET_RPC_ERROR_CODE_BAD_TX_METADATA             = -27;
constexpr int64_t WALLET_RPC_ERROR_CODE_ALREADY_MULTISIG            = -28;
constexpr int64_t WALLET_RPC_ERROR_CODE_WATCH_ONLY                  = -29;
constexpr int64_t WALLET_RPC_ERROR_CODE_BAD_MULTISIG_INFO           = -30;
constexpr int64_t WALLET_RPC_ERROR_CODE_NOT_MULTISIG                = -31;
constexpr int64_t WALLET_RPC_ERROR_CODE_WRONG_LR                    = -32;
constexpr int64_t WALLET_RPC_ERROR_CODE_THRESHOLD_NOT_REACHED       = -33;
constexpr int64_t WALLET_RPC_ERROR_CODE_BAD_MULTISIG_TX_DATA        = -34;
constexpr int64_t WALLET_RPC_ERROR_CODE_MULTISIG_SIGNATURE          = -35;
constexpr int64_t WALLET_RPC_ERROR_CODE_MULTISIG_SUBMISSION         = -36;
constexpr int64_t WALLET_RPC_ERROR_CODE_NOT_ENOUGH_UNLOCKED_MONEY   = -37;
constexpr int64_t WALLET_RPC_ERROR_CODE_NO_DAEMON_CONNECTION        = -38;
constexpr int64_t WALLET_RPC_ERROR_CODE_BAD_UNSIGNED_TX_DATA        = -39;
constexpr int64_t WALLET_RPC_ERROR_CODE_BAD_SIGNED_TX_DATA          = -40;
constexpr int64_t WALLET_RPC_ERROR_CODE_SIGNED_SUBMISSION           = -41;
constexpr int64_t WALLET_RPC_ERROR_CODE_SIGN_UNSIGNED               = -42;
constexpr int64_t WALLET_RPC_ERROR_CODE_NON_DETERMINISTIC           = -43;
constexpr int64_t WALLET_RPC_ERROR_CODE_INVALID_LOG_LEVEL           = -44;
constexpr int64_t WALLET_RPC_ERROR_CODE_ATTRIBUTE_NOT_FOUND         = -45;
constexpr int64_t WALLET_RPC_ERROR_CODE_INVALID_SIGNATURE_TYPE      = -47;
