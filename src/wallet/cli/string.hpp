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

  constexpr char USAGE_START_MINING[] = "start-mining [<number_of_threads>]";
  constexpr char USAGE_SET_DAEMON[] = "set-daemon <host>[:<port>]";
  constexpr char USAGE_SHOW_BALANCE[] = "balance [detail]";
  constexpr char USAGE_INCOMING[] = "incoming [available|unavailable] [verbose] [index=<N1>[,<N2>[,...]]]";
  constexpr char USAGE_TRANSFER[] = "transfer [index=<N1>[,<N2>,...]] [<priority>] (<URI> | <address> <amount>)";
  constexpr char USAGE_SET_LOG[] = "set-log <level>";
  constexpr char USAGE_ACCOUNT[] = "account\n"
                            "  account new <label>\n"
                            "  account switch <index> \n"
                            "  account label <index> <label>\n"
                            ;
  constexpr char USAGE_ADDRESS[] = "address\n"
                            "  address new <label>\n"
                            "  address all \n"
                            "  address <index min> [<index max>]\n"
                            "  address label <index> <label>\n"
                            "  address one-off <account> <subaddress>\n"
                            ;
  constexpr char USAGE_SET_VARIABLE[] = "set <option> [<value>]";
  constexpr char USAGE_GET_TX_OUTPUT_SECRET_KEYS[] = "get-tx-output-secret-keys <txid>";
  constexpr char USAGE_GET_TX_PROOF[] = "get-tx-proof <txid> <address> [<message>]";
  constexpr char USAGE_VERIFY_TX_PROOF[] = "verify-tx-proof <txid> <address> <signature file> [<message>]";
  constexpr char USAGE_SHOW[] = "show [in|out|all|pending|failed|pool|coinbase] [index=<N1>[,<N2>,...]]\n"
                          "     [<min height> [<max height>]]\n";
  constexpr char USAGE_UTXOS[] = "utxos [index=<N1>[,<N2>,...]] [<min amount> [<max amount>]]";
  constexpr char USAGE_RESCAN[] = "rescan [hard]";
  constexpr char USAGE_SIGN[] = "sign [<account index>,<address index>] [--spend|--view] <filename>";
  constexpr char USAGE_VERIFY[] = "verify <filename> <address> <signature>";
  constexpr char USAGE_SHOW_TX[] = "tx <txid>";
  constexpr char USAGE_WELCOME[] = "welcome";
  constexpr char USAGE_VERSION[] = "version";
  constexpr char USAGE_HELP[] = "help [<command> | all]";
} // usage

namespace help {
  constexpr std::string_view incoming =
    "Show the incoming transfers, all or filtered by availability and address index.\n\n"
    "Output format:\n"
    "Amount, Spent(\"T\"|\"F\"), \"frozen\"|\"locked\"|\"unlocked\", "
    "RingCT, Global Index, Transaction Hash, Address Index, [Public Key, Key Image] ";

  constexpr std::string_view transfer =
    "Transfer <amount> to <address>. If the parameter \"index=<N1>[,<N2>,...]\" is specified, the wallet uses outputs received by addresses of those indices. If omitted, the wallet randomly chooses address indices to be used. In any case, it tries its best not to combine outputs across multiple addresses. <priority> is the priority of the transaction. The higher the priority, the higher the transaction fee. Valid values in priority order (from lowest to highest) are: unimportant, normal, elevated, priority. If omitted, the default value (see the command \"set priority\") is used. <ring_size> is the number of inputs to include for untraceability. Multiple payments can be made at once by adding URI_2 or <address_2> <amount_2> etcetera (before the payment ID, if it's included)";

  constexpr std::string_view account =
    "If no arguments are specified, the wallet shows all the existing accounts along with their balances.\n"
    "If the \"new\" argument is specified, the wallet creates a new account with its label initialized by the provided label text (which can be empty).\n"
    "If the \"switch\" argument is specified, the wallet switches to the account specified by <index>.\n"
    "If the \"label\" argument is specified, the wallet sets the label of the account specified by <index> to the provided label text.\n";

  constexpr std::string_view address =
    "If no arguments are specified or <index> is specified, the wallet shows the default or specified address. If \"all\" is specified, the wallet shows all the existing addresses in the currently selected account. If \"new \" is specified, the wallet creates a new address with the provided label text (which can be empty). If \"label\" is specified, the wallet sets the label of the address specified by <index> to the provided label text. If \"one-off\" is specified, the address for the specified index is generated and displayed, and remembered by the wallet";

  constexpr std::string_view show =
    "Show the incoming/outgoing transfers within an optional height range.\n\n"
    "Output format:\n"
    "In or Coinbase:    Block Number, \"block\"|\"in\",              Time, Amount,  Transaction Hash, Payment ID, Subaddress Index,                     \"-\", Note\n"
    "Out:               Block Number, \"out\",                     Time, Amount*, Transaction Hash, Payment ID, Fee, Destinations, Input addresses**, \"-\", Note\n"
    "Pool:                            \"pool\", \"in\",              Time, Amount,  Transaction Hash, Payment Id, Subaddress Index,                     \"-\", Note, Double Spend Note\n"
    "Pending or Failed:               \"failed\"|\"pending\", \"out\", Time, Amount*, Transaction Hash, Payment ID, Fee, Input addresses**,               \"-\", Note\n\n"
    "* Excluding change and fee.\n"
    "** Set of address indices used as inputs in this transfer.";

  constexpr std::string_view set_variable =
    "Available options:\n "
    "always-confirm-transfers <1|0>\n "
    "  Whether to confirm unsplit txes.\n "
    "print-ring-members <1|0>\n "
    "  Whether to print detailed information about ring members during confirmation.\n "
    "store-tx-info <1|0>\n "
    "  Whether to store outgoing tx info (destination address, payment ID, tx secret key) for future reference.\n "
    "priority [0|1|2|3|4]\n "
    "  Set the fee to default/unimportant/normal/elevated/priority.\n "
    "unit <lolnero|millinero|micronero|nanonero|piconero>\n "
    "  Set the default lolnero (sub-)unit.\n "
    "min-outputs-count [n]\n "
    "  Try to keep at least that many outputs of value at least min-outputs-value.\n "
    "min-outputs-value [n]\n "
    "  Try to keep at least min-outputs-count outputs of at least that value.\n "
    "merge-destinations <1|0>\n "
    "  Whether to merge multiple payments to the same destination address.\n "
    "confirm-export-overwrite <1|0>\n "
    "  Whether to warn if the file to be exported already exists.\n "
    "refresh-from-block-height [n]\n "
    "  Set the height before which to ignore blocks.\n "
    "subaddress-lookahead <major>:<minor>\n "
    "  Set the lookahead sizes for the subaddress hash table.\n "
    "ignore-fractional-outputs <1|0>\n "
    "  Whether to ignore fractional outputs that result in net loss when spending due to fee.\n ";
} // help

namespace arg {
  const command_line::arg_descriptor<std::string> arg_generate_new_wallet =
    {"new", ("Generate new wallet and save it to <arg>"), ""};

  const command_line::arg_descriptor<std::string> arg_generate_from_spend_key =
    {"generate-from-spend-key", ("Generate deterministic wallet from spend key"), ""};

  const command_line::arg_descriptor<std::string> arg_electrum_seed =
    {"electrum-seed", ("Specify Electrum seed for wallet recovery/creation"), ""};

  const command_line::arg_descriptor<bool> arg_restore_deterministic_wallet =
    {"restore", ("Recover wallet using Electrum-style mnemonic seed"), false};

  const command_line::arg_descriptor<bool> arg_do_not_relay =
    {"do-not-relay", ("The newly created transaction will not be relayed to the lolnero network"), false};

  const command_line::arg_descriptor<std::string> arg_subaddress_lookahead =
    {"subaddress-lookahead", ("Set subaddress lookahead sizes to <major>:<minor>"), ""};

  const command_line::arg_descriptor< std::vector<std::string> > arg_command = {"command", ""};
}

} // wallet
