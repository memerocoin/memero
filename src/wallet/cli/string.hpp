// Copyright (c) 2021, The Lolnero Project
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

#include "tools/common/command_line.h"

namespace wallet
{
namespace usage
{
  constexpr char USAGE_START_MINING[] =
    "start-mining [<number_of_threads>]";

  constexpr char USAGE_SHOW_BALANCE[] =
    "balance [detail]";

  constexpr char USAGE_INCOMING[] =
    "in [available|unavailable] [verbose] [index=<N1>[,<N2>[,...]]]";
  constexpr char USAGE_TRANSFER[] =
    "transfer [output index=<N1>[,<N2>,...]] "
    "[<priority>] (<address> <amount>)";

  constexpr char USAGE_ACCOUNT[] =
    "account\n"
    "  account new <label>\n"
    "  account switch <index> \n"
    "  account label <index> <label>\n"
    ;

  constexpr char USAGE_ADDRESS[] =
    "address\n"
    "  address new <label>\n"
    "  address all \n"
    "  address <index min> [<index max>]\n"
    "  address label <index> <label>\n"
    "  address one-off <account> <subaddress>\n"
    ;

  constexpr char USAGE_SET_VARIABLE[] = "set <option> [<value>]";
  constexpr char USAGE_GET_TX_SENDER_SIGNATURE[] =
    "get-output-ecdh-signatures <txid> <address> [<message>]";

  constexpr char USAGE_VERIFY_TX_SENDER_SIGNATURE[] =
    "verify-output-ecdh-signatures <txid> <address> "
    "<signature file> [<message>]";

  constexpr char USAGE_SHOW[] =
    "show [in|out|all|pending|failed|pool|coinbase] "
    "[index=<N1>[,<N2>,...]]\n"
    "     [<min height> [<max height>]]\n";

  constexpr char USAGE_RESCAN[] = "rescan [hard]";
  constexpr char USAGE_SHOW_TX[] = "tx <txid>";
  constexpr char USAGE_VERSION[] = "version";
  constexpr char USAGE_HELP[] = "help [<command> | all]";
} // usage

namespace help {
  constexpr std::string_view incoming = " ";
  constexpr std::string_view transfer = " ";
  constexpr std::string_view account = " ";
  constexpr std::string_view address = " ";
  constexpr std::string_view show = " ";
  constexpr std::string_view set_variable =
    "Available options:\n "
    "always-confirm-transfers <1|0>\n "
    "  Whether to confirm unsplit txes.\n "
    "store-tx-info <1|0>\n "
    "  Whether to store outgoing tx info.\n "
    "priority [0|1|2|3|4]\n "
    "  Set the fee from low to high.\n"
    "unit <lolnero|millinero|micronero|nanonero|piconero>\n "
    "  Set the default lolnero (sub-)unit.\n "
    "min-outputs-count [n]\n "
    "  Minimum number of outputs to keep.\n "
    "min-outputs-value [n]\n "
    "  A (max) bound of amount to ignore.\n "
    "merge-destinations <1|0>\n "
    "  Whether to merge multiple payments to the same destination.\n "
    "confirm-export-overwrite <1|0>\n "
    "  Warn if the file to be exported already exists.\n "
    "refresh-from-block-height [n]\n "
    "  Set the height before which to ignore blocks.\n "
    "subaddress-lookahead <account>:<subaddress>\n "
    "  Set the index bound for scanning.\n "
    "ignore-fractional-outputs <1|0>\n "
    "  Ignore outputs with value below min-outputs-value\n"
    ;
} // help

namespace arg {
  const command_line::arg_descriptor<std::string>
  arg_generate_new_wallet =
    {
      "new"
      , ("Generate new wallet and save it to <arg>")
      , ""
    };

  const command_line::arg_descriptor<std::string>
  arg_generate_from_spend_key =
    {
      "generate-from-spend-key"
      , ("Generate deterministic wallet from spend key")
      , ""
    };

  const command_line::arg_descriptor<std::string>
  arg_electrum_seed =
    {
      "electrum-seed"
      , ("Specify Electrum seed for wallet recovery/creation")
      , ""
    };

  const command_line::arg_descriptor<bool>
  arg_restore_deterministic_wallet =
    {
      "restore"
      , ("Recover wallet using Electrum-style mnemonic seed")
      , false
    };

  const command_line::arg_descriptor<bool> arg_do_not_relay =
    {
      "do-not-relay"
      , ("New transactions will not be relayed to the network")
      , false
    };

  const command_line::arg_descriptor<std::string>
  arg_subaddress_lookahead =
    {
      "subaddress-lookahead"
      , ("Set subaddress lookahead sizes to <account>:<subaddress>")
      , ""
    };
}

} // wallet
