// Copyright (c) 2020-2021, The Lolnero Project
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

#include "wallet2.h"

#include "wallet/logic/functional/fee.hpp"
#include "wallet/logic/functional/signature.hpp"
#include "wallet/logic/functional/wallet.hpp"
#include "wallet/logic/functional/helper.hpp"
#include "wallet/logic/pseudo_functional/proof.hpp"
#include "wallet/logic/controller/proof.hpp"
#include "wallet/logic/controller/wallet.hpp"

#include "math/blockchain/functional/subaddress.hpp"

#include "wallet/mnemonics/electrum-words.h"

#include "network/rpc/core_rpc_server_error_codes.h"

#include "math/ringct/pseudo_functional/ringCT.hpp"
#include "math/crypto/controller/random.hpp"

#include "cryptonote/tx/functional/tx_check.h"
#include "cryptonote/basic/functional/tx_extra.hpp"


#include "tools/common/apply_permutation.h"
#include "tools/common/command_line.h"
#include "tools/common/json_util.h"
#include "tools/common/threadpool.h"
#include "tools/common/util.h"
#include "tools/epee/include/profile_tools.h"
#include "tools/serialization/binary_utils.h"


#include <boost/format.hpp>
#include <boost/exception/to_string.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string.hpp>

#include <rapidjson/document.h>
#include <rapidjson/writer.h>


using namespace cryptonote;
using namespace wallet::logic::functional::fee;
using namespace wallet::logic::type::message_signature;





// used to target a given block weight (additional outputs may be added on top to build fee)
constexpr uint64_t TX_WEIGHT_TARGET(const uint64_t bytes) {
  return bytes * 2 / 3;
}

namespace
{
// Create on-demand to prevent static initialization order fiasco issues.
struct options {
  const command_line::arg_descriptor<std::string> daemon_address =
    {"daemon-address", tools::wallet2::tr("Use daemon instance at <host>:<port>"), ""};

  const command_line::arg_descriptor<std::string> password =
    {"password", tools::wallet2::tr("Wallet password (escape/quote as needed)"), "", true};

  const command_line::arg_descriptor<std::string> password_file =
    {"password-file", tools::wallet2::tr("Wallet password file"), "", true};

  const command_line::arg_descriptor<bool> testnet =
    {"testnet", tools::wallet2::tr("For testnet. Daemon must also be launched with --testnet flag"), false};

  const command_line::arg_descriptor<uint64_t> kdf_rounds =
    {"kdf-rounds", tools::wallet2::tr("Number of rounds for the key derivation function"), 1};

  const command_line::arg_descriptor<bool> offline =
    {"offline", tools::wallet2::tr("Do not connect to a daemon"), false};
};

std::unique_ptr<tools::wallet2> make_basic(const boost::program_options::variables_map& vm, bool unattended, const options& opts, const std::function<std::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  const bool testnet = command_line::get_arg(vm, opts.testnet);
  const network_type nettype = testnet ? TESTNET : MAINNET;
  const uint64_t kdf_rounds = command_line::get_arg(vm, opts.kdf_rounds);
  THROW_WALLET_EXCEPTION_IF(kdf_rounds == 0, tools::error::wallet_internal_error, "KDF rounds must not be 0");

  auto daemon_address = command_line::get_arg(vm, opts.daemon_address);
  const std::string daemon_host(config::lol::RPC_DEFAULT_HOST);
  const auto daemon_port = get_config(nettype).RPC_DEFAULT_PORT;

  if (daemon_address.empty())
    daemon_address = daemon_host + ":" + std::to_string(daemon_port);

  std::unique_ptr<tools::wallet2> wallet = std::make_unique<tools::wallet2>(nettype, kdf_rounds, unattended);
  if (!wallet->init(std::move(daemon_address)))
  {
    THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to initialize the wallet"));
  }

  if (command_line::get_arg(vm, opts.offline))
    wallet->set_offline();

  return wallet;
}

std::optional<tools::password_container> get_password(const boost::program_options::variables_map& vm, const options& opts, const std::function<std::optional<tools::password_container>(const char*, bool)> &password_prompter, const bool verify)
{
  if (command_line::has_arg(vm, opts.password) && command_line::has_arg(vm, opts.password_file))
  {
    THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("can't specify more than one of --password and --password-file"));
  }

  if (command_line::has_arg(vm, opts.password))
  {
    return tools::password_container{command_line::get_arg(vm, opts.password)};
  }

  if (command_line::has_arg(vm, opts.password_file))
  {
    std::string password;
    bool r = epee::file_io_utils::load_file_to_string(command_line::get_arg(vm, opts.password_file),
                                                      password);
    THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, tools::wallet2::tr("the password file specified could not be read"));

    // Remove line breaks the user might have inserted
    boost::trim_right_if(password, boost::is_any_of("\r\n"));
    return {tools::password_container{std::move(password)}};
  }

  THROW_WALLET_EXCEPTION_IF(!password_prompter, tools::error::wallet_internal_error, tools::wallet2::tr("no password specified; use --prompt-for-password to prompt for a password"));

  return password_prompter(verify ? tools::wallet2::tr("Enter a new password for the wallet") : tools::wallet2::tr("Wallet password"), verify);
}

static bool emplace_or_replace(std::unordered_multimap<crypto::hash, wallet::logic::type::payment::pool_payment_details> &container,
                               const wallet::logic::type::payment::pool_payment_details &pd)
{
  crypto::hash key = crypto::null_hash;
  auto range = container.equal_range(key);
  for (auto i = range.first; i != range.second; ++i)
  {
    if (i->second.m_pd.m_tx_hash == pd.m_pd.m_tx_hash && i->second.m_pd.m_subaddr_index == pd.m_pd.m_subaddr_index)
    {
      i->second = pd;
      return false;
    }
  }
  container.emplace(key, pd);
  return true;
}

void drop_from_short_history(std::list<crypto::hash> &short_chain_history, size_t N)
{
  std::list<crypto::hash>::iterator right;
  // drop early N off, skipping the genesis block
  if (short_chain_history.size() > N) {
    right = short_chain_history.end();
    std::advance(right,-1);
    std::list<crypto::hash>::iterator left = right;
    std::advance(left, -N);
    short_chain_history.erase(left, right);
  }
}

bool get_full_tx(const cryptonote::COMMAND_RPC_GET_TRANSACTIONS::entry &entry, cryptonote::transaction &tx, crypto::hash &tx_hash)
{
  cryptonote::string_blob bd;

  // easy case if we have the whole tx
  if (!entry.as_hex.empty())
  {
    LOG_ERROR_AND_RETURN_UNLESS(epee::string_tools::parse_hexstr_to_binbuff(entry.as_hex, bd), false, "Failed to parse tx data");
    const auto maybeTx = maybe_tx_from_blob(bd);
    LOG_ERROR_AND_RETURN_UNLESS(maybeTx, false, "Invalid tx data");
    tx = *maybeTx;

    tx_hash = cryptonote::get_transaction_hash(tx);
    // if the hash was given, check it matches
    LOG_ERROR_AND_RETURN_UNLESS(entry.tx_hash.empty() || epee::string_tools::pod_to_hex(tx_hash) == entry.tx_hash, false,
        "Response claims a different hash than the data yields");
    return true;
  }
  return false;
}

  //-----------------------------------------------------------------
} //namespace

namespace tools
{
constexpr const std::chrono::seconds wallet2::rpc_timeout;
const char* wallet2::tr(const char* str) { return str; }

wallet2::wallet2(network_type nettype, uint64_t kdf_rounds, bool unattended):
  m_run(true),
  m_callback(0),
  m_nettype(nettype),
  m_always_confirm_transfers(true),
  m_print_ring_members(false),
  m_store_tx_info(true),
  m_default_priority(0),
  m_refresh_from_block_height(0),
  m_explicit_refresh_from_block_height(true),
  m_ask_password(AskPasswordNever),
  m_merge_destinations(false),
  m_confirm_export_overwrite(true),
  m_ignore_fractional_outputs(true),
  m_ignore_outputs_above(std::numeric_limits<uint64_t>::max()),
  m_ignore_outputs_below(0),
  m_is_initialized(false),
  m_kdf_rounds(kdf_rounds),
  m_rpc_client(),
  m_spend_view_public_keys{crypto::null_pkey, crypto::null_pkey},
  m_subaddress_lookahead_major(config::lol::SUBADDRESS_LOOKAHEAD_MAJOR),
  m_subaddress_lookahead_minor(config::lol::SUBADDRESS_LOOKAHEAD_MINOR),
  m_offline(false),
  m_rpc_version(0)
{
}

wallet2::~wallet2()
{
}

void wallet2::init_options(boost::program_options::options_description& desc_params)
{
  const options opts{};
  command_line::add_arg(desc_params, opts.daemon_address);
  command_line::add_arg(desc_params, opts.password);
  command_line::add_arg(desc_params, opts.password_file);
  command_line::add_arg(desc_params, opts.testnet);
  command_line::add_arg(desc_params, opts.kdf_rounds);
  command_line::add_arg(desc_params, opts.offline);
}

std::pair<std::unique_ptr<wallet2>, password_container> wallet2::make_from_file(
  const boost::program_options::variables_map& vm, bool unattended, const std::string& wallet_file, const std::function<std::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  const options opts{};
  auto pwd = get_password(vm, opts, password_prompter, false);
  if (!pwd)
  {
    return {nullptr, password_container{}};
  }
  auto wallet = make_basic(vm, unattended, opts, password_prompter);
  if (wallet && !wallet_file.empty())
  {
    wallet->load(wallet_file, pwd->password());
  }
  return {std::move(wallet), std::move(*pwd)};
}

std::pair<std::unique_ptr<wallet2>, password_container> wallet2::make_new(const boost::program_options::variables_map& vm, bool unattended, const std::function<std::optional<password_container>(const char *, bool)> &password_prompter)
{
  const options opts{};
  auto pwd = get_password(vm, opts, password_prompter, true);
  if (!pwd)
  {
    return {nullptr, password_container{}};
  }
  return {make_basic(vm, unattended, opts, password_prompter), std::move(*pwd)};
}

//----------------------------------------------------------------------------------------------------
bool wallet2::set_daemon(std::string daemon_address)
{
  std::vector<std::string> tokens;
  boost::split(tokens, daemon_address, boost::is_any_of(":"));


  if (tokens.size() == 2) {
    m_daemon_host = tokens.front();
    m_daemon_port = tokens.back();

    const std::string address = get_daemon_address();
    LOG_INFO("setting daemon to " << address);

    m_rpc_client.set_daemon(m_daemon_host, m_daemon_port);

    return true;
  }

  else {
    LOG_FATAL("failed to set daemon address: " << daemon_address);
    return false;
  }

}
//----------------------------------------------------------------------------------------------------
bool wallet2::init(std::string daemon_address)
{
  m_is_initialized = true;
  return set_daemon(daemon_address);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::get_seed(epee::wipeable_string& electrum_words, const epee::wipeable_string &passphrase)
{
  if (seed_language.empty())
  {
    std::vector<std::string> language_list_self;
    crypto::ElectrumWords::get_language_list(language_list_self, false);
    const std::string language = language_list_self[0];
    set_seed_language(language);
  }

  crypto::secret_key key = get_account().get_keys().m_spend_secret_key;
  if (!passphrase.empty())
    key = cryptonote::encrypt_key(key, passphrase);
  if (!crypto::ElectrumWords::bytes_to_words(key, electrum_words, seed_language))
  {
    std::cout << "Failed to create seed from key for language: " << seed_language << std::endl;
    return false;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
/*!
 * \brief Gets the seed language
 */
const std::string &wallet2::get_seed_language() const
{
  return seed_language;
}
/*!
 * \brief Sets the seed language
 * \param language  Seed language to set to
 */
void wallet2::set_seed_language(const std::string &language)
{
  seed_language = language;
}
//----------------------------------------------------------------------------------------------------
cryptonote::spend_view_public_keys wallet2::get_subaddress(const cryptonote::subaddress_index& index) const
{
  return cryptonote::get_subaddress(m_account.get_spend_view_secret_keys(), index);
}
//----------------------------------------------------------------------------------------------------
std::optional<cryptonote::subaddress_index> wallet2::get_subaddress_index(const cryptonote::spend_view_public_keys& address) const
{
  auto index = m_subaddresses.find(address.m_spend_public_key);
  if (index == m_subaddresses.end())
    return std::nullopt;
  return index->second;
}
//----------------------------------------------------------------------------------------------------
crypto::public_key wallet2::get_subaddress_spend_public_key(const cryptonote::subaddress_index& index) const
{
  return cryptonote::get_subaddress_spend_public_key(m_account.get_spend_view_secret_keys(), index);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::get_subaddress_as_str(const cryptonote::subaddress_index& index) const
{
  cryptonote::spend_view_public_keys address = get_subaddress(index);
  return cryptonote::get_account_address_as_str(m_nettype, !index.is_zero(), address);
}
//----------------------------------------------------------------------------------------------------
void wallet2::add_subaddress_account(const std::string& label)
{
  uint32_t index_major = (uint32_t)get_num_subaddress_accounts();
  expand_subaddresses({index_major, 0});
  m_subaddress_labels[index_major][0] = label;
}
//----------------------------------------------------------------------------------------------------
void wallet2::add_subaddress(uint32_t index_major, const std::string& label)
{
  THROW_WALLET_EXCEPTION_IF(index_major >= m_subaddress_labels.size(), error::account_index_outofbound);
  uint32_t index_minor = (uint32_t)get_num_subaddresses(index_major);
  expand_subaddresses({index_major, index_minor});
  m_subaddress_labels[index_major][index_minor] = label;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::should_expand(const cryptonote::subaddress_index &index) const
{
  const uint32_t last_major = m_subaddress_labels.size() - 1 > (std::numeric_limits<uint32_t>::max() - m_subaddress_lookahead_major) ? std::numeric_limits<uint32_t>::max()  : (m_subaddress_labels.size() + m_subaddress_lookahead_major - 1);
  if (index.major > last_major)
    return false;
  const size_t nsub = index.major < m_subaddress_labels.size() ? m_subaddress_labels[index.major].size() : 0;
  const uint32_t last_minor = nsub - 1 > (std::numeric_limits<uint32_t>::max() - m_subaddress_lookahead_minor) ? std::numeric_limits<uint32_t>::max()  : (nsub + m_subaddress_lookahead_minor - 1);
  if (index.minor > last_minor)
    return false;
  return true;
}
//----------------------------------------------------------------------------------------------------
void wallet2::expand_subaddresses(const cryptonote::subaddress_index& index)
{
  if (m_subaddress_labels.size() <= index.major)
  {
    // add new accounts
    cryptonote::subaddress_index index2;
    const uint32_t major_end = wallet::logic::functional::wallet::get_subaddress_clamped_sum
      (index.major, m_subaddress_lookahead_major);
    for (index2.major = m_subaddress_labels.size(); index2.major < major_end; ++index2.major)
    {
      const uint32_t end = wallet::logic::functional::wallet::get_subaddress_clamped_sum
        ((index2.major == index.major ? index.minor : 0), m_subaddress_lookahead_minor);
      const std::vector<crypto::public_key> pkeys =
        cryptonote::get_subaddress_spend_public_keys
        (m_account.get_spend_view_secret_keys(), index2.major, 0, end);

      for (index2.minor = 0; index2.minor < end; ++index2.minor)
      {
         const crypto::public_key &D = pkeys[index2.minor];
         m_subaddresses[D] = index2;
      }
    }
    m_subaddress_labels.resize(index.major + 1);
    m_subaddress_labels[index.major].resize(index.minor + 1);
  }
  else if (m_subaddress_labels[index.major].size() <= index.minor)
  {
    // add new subaddresses
    const uint32_t end = wallet::logic::functional::wallet::get_subaddress_clamped_sum
      (index.minor, m_subaddress_lookahead_minor);
    const uint32_t begin = m_subaddress_labels[index.major].size();
    cryptonote::subaddress_index index2 = {index.major, begin};
    const std::vector<crypto::public_key> pkeys =
      cryptonote::get_subaddress_spend_public_keys
      (m_account.get_spend_view_secret_keys(), index2.major, index2.minor, end);
    for (; index2.minor < end; ++index2.minor)
    {
       const crypto::public_key &D = pkeys[index2.minor - begin];
       m_subaddresses[D] = index2;
    }
    m_subaddress_labels[index.major].resize(index.minor + 1);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::create_one_off_subaddress(const cryptonote::subaddress_index& index)
{
  const crypto::public_key pkey = get_subaddress_spend_public_key(index);
  m_subaddresses[pkey] = index;
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::get_subaddress_label(const cryptonote::subaddress_index& index) const
{
  if (index.major >= m_subaddress_labels.size() || index.minor >= m_subaddress_labels[index.major].size())
  {
    LOG_ERROR("Subaddress label doesn't exist");
    return "";
  }
  return m_subaddress_labels[index.major][index.minor];
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_subaddress_label(const cryptonote::subaddress_index& index, const std::string &label)
{
  THROW_WALLET_EXCEPTION_IF(index.major >= m_subaddress_labels.size(), error::account_index_outofbound);
  THROW_WALLET_EXCEPTION_IF(index.minor >= m_subaddress_labels[index.major].size(), error::address_index_outofbound);
  m_subaddress_labels[index.major][index.minor] = label;
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_subaddress_lookahead(size_t major, size_t minor)
{
  THROW_WALLET_EXCEPTION_IF(major == 0, error::wallet_internal_error, "Subaddress major lookahead may not be zero");
  THROW_WALLET_EXCEPTION_IF(major > 0xffffffff, error::wallet_internal_error, "Subaddress major lookahead is too large");
  THROW_WALLET_EXCEPTION_IF(minor == 0, error::wallet_internal_error, "Subaddress minor lookahead may not be zero");
  THROW_WALLET_EXCEPTION_IF(minor > 0xffffffff, error::wallet_internal_error, "Subaddress minor lookahead is too large");
  m_subaddress_lookahead_major = major;
  m_subaddress_lookahead_minor = minor;
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_spent(size_t idx, uint64_t height)
{
  LOG_ERROR_AND_THROW_UNLESS(idx < m_transfers.size(), "Invalid index");
  transfer_details &td = m_transfers[idx];
  LOG_PRINT_L3("Setting SPENT at " << height << ": ki " << td.m_output_key_image << ", amount " << print_money(td.m_amount));
  td.m_spent = true;
  td.m_spent_height = height;
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_unspent(size_t idx)
{
  LOG_ERROR_AND_THROW_UNLESS(idx < m_transfers.size(), "Invalid index");
  transfer_details &td = m_transfers[idx];
  LOG_PRINT_L3("Setting UNSPENT: ki " << td.m_output_key_image << ", amount " << print_money(td.m_amount));
  td.m_spent = false;
  td.m_spent_height = 0;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_spent(size_t idx, bool strict) const
{
  LOG_ERROR_AND_THROW_UNLESS(idx < m_transfers.size(), "Invalid index");
  const transfer_details &td = m_transfers[idx];
  return wallet::logic::functional::wallet::is_spent(td, strict);
}
//----------------------------------------------------------------------------------------------------
size_t wallet2::get_transfer_details(const crypto::key_image &ki) const
{
  for (size_t idx = 0; idx < m_transfers.size(); ++idx)
  {
    const transfer_details &td = m_transfers[idx];
    if (td.m_output_key_image_known && td.m_output_key_image == ki)
      return idx;
  }
  LOG_ERROR_AND_THROW_UNLESS(false, "Key image not found");
}
//----------------------------------------------------------------------------------------------------
bool wallet2::spends_one_of_ours(const cryptonote::transaction &tx) const
{
  for (const auto &in: tx.vin)
  {
    if (in.type() != typeid(cryptonote::txin_from_key))
      continue;
    const cryptonote::txin_from_key &in_to_key = boost::get<cryptonote::txin_from_key>(in);
    auto it = m_output_key_images.find(in_to_key.output_key_image);
    if (it != m_output_key_images.end())
      return true;
  }
  return false;
}
//----------------------------------------------------------------------------------------------------
void wallet2::process_new_transaction(const crypto::hash &txid, const cryptonote::transaction& tx, const std::vector<uint64_t> &o_indices, uint64_t height, uint8_t block_version, uint64_t ts, bool miner_tx, bool pool, bool double_spend_seen)
{
  // In this function, tx (probably) only contains the base information
  // (that is, the prunable stuff may or may not be included)
  if (!miner_tx && !pool)
    process_unconfirmed(txid, tx, height);

  // per receiving subaddress index
  std::unordered_map<cryptonote::subaddress_index, uint64_t> tx_money_got_in_outs;
  std::unordered_map<cryptonote::subaddress_index, amounts_container> tx_amounts_individual_outs;

  // Don't try to extract tx public key if tx has no ouputs
  uint64_t total_received_1 = 0;

  const cryptonote::account_keys& keys = m_account.get_keys();

  const bool tx_locked_too_far_away =
    (tx.unlock_height >= height) && (tx.unlock_height - height) > config::lol::tx_locked_one_year_away_in_blocks;

  if (tx_locked_too_far_away) {
    LOG_DEBUG("Found a tx locked one year way, not considering its outputs as valid for now.");
  }

  if (!tx.vout.empty() && !tx_locked_too_far_away)
  {
    std::vector<size_t> outs;
    // if tx.vout is not empty, we loop through all tx pubkeys

    // const size_t vout_size = tx.vout.size();

    std::map<size_t, crypto::ecdh_shared_secret> tx_output_shared_secrets;

    const auto output_ecdh_public_keys
      = get_all_output_ecdh_public_keys_from_extra(tx.extra, tx.vout.size());

    if (output_ecdh_public_keys)
    {
      for (size_t i = 0; i < output_ecdh_public_keys->size(); ++i)
      {
        tx_output_shared_secrets[i] =
          crypto::derive_tx_output_ecdh_shared_secret(output_ecdh_public_keys->at(i), keys.m_view_secret_key);
      }
    }

    int num_vouts_received = 0;
    std::vector<tx_scan_info_t> tx_scan_info;
    for (size_t i = 0; i < tx.vout.size(); ++i)
    {
      const auto secret
        = tx_output_shared_secrets.contains(i)
        ? tx_output_shared_secrets.at(i)
        : std::optional<crypto::ecdh_shared_secret>();

      if (!secret) continue;

      const tx_scan_info_t check_info = wallet::logic::functional::wallet::scan_output_for_subaddresses
        (tx.vout[i], *secret, i, m_subaddresses);

      THROW_WALLET_EXCEPTION_IF
        (
         check_info.error
         , error::acc_outs_lookup_error
         , tx
         , crypto::null_pkey
         , m_account.get_keys()
         );


      if (check_info.received)
      {
        const tx_scan_info_t scan_info = wallet::logic::functional::wallet::scan_output
          (
            tx
            , miner_tx
            , i
            , check_info
            , outs
            , m_account.get_keys()
            );

        if (!scan_info.error)
        {
          num_vouts_received++;
          outs.push_back(i);

          THROW_WALLET_EXCEPTION_IF
            (
              tx_money_got_in_outs[scan_info.received->index]
              >= std::numeric_limits<uint64_t>::max() - scan_info.money_transfered
              , error::wallet_internal_error
              , "Overflow in received amounts"
              );

          tx_money_got_in_outs[scan_info.received->index] += scan_info.money_transfered;

          tx_amounts_individual_outs[scan_info.received->index].push_back(scan_info.money_transfered);

          tx_scan_info.push_back(scan_info);
        }
      }
      else {
        tx_scan_info.push_back(check_info);
      }
    }

    if(!outs.empty() && num_vouts_received > 0)
    {
      //good news - got money! take care about it
      //usually we have only one transfer for user in transaction
      if (!pool)
      {
        THROW_WALLET_EXCEPTION_IF(tx.vout.size() != o_indices.size(), error::wallet_internal_error,
            "transactions outputs size=" + std::to_string(tx.vout.size()) +
            " not match with daemon response size=" + std::to_string(o_indices.size()));
      }

      for(size_t o: outs)
      {
	THROW_WALLET_EXCEPTION_IF(tx.vout.size() <= o, error::wallet_internal_error, "wrong out in transaction: internal index=" +
				  std::to_string(o) + ", total_outs=" + std::to_string(tx.vout.size()));

        auto kit = m_pub_keys.find(tx_scan_info[o].output_key_pair.pub);
	THROW_WALLET_EXCEPTION_IF(kit != m_pub_keys.end() && kit->second >= m_transfers.size(),
            error::wallet_internal_error, std::string("Unexpected transfer index from public key: ")
            + "got " + (kit == m_pub_keys.end() ? "<none>" : boost::lexical_cast<std::string>(kit->second))
            + ", m_transfers.size() is " + boost::lexical_cast<std::string>(m_transfers.size()));
        if (kit == m_pub_keys.end())
        {
          uint64_t amount = tx.vout[o].amount ? tx.vout[o].amount : tx_scan_info[o].amount;
          if (!pool)
          {
	    m_transfers.push_back(transfer_details{});
	    transfer_details& td = m_transfers.back();
	    td.m_block_height = height;
	    td.m_internal_output_index = o;
	    td.m_global_output_index = o_indices[o];
	    td.m_tx = (const cryptonote::transaction_prefix&)tx;
	    td.m_txid = txid;
            td.m_output_key_image = tx_scan_info[o].ki;
            td.m_output_key_image_known = true;
            if (!td.m_output_key_image_known)
            {
              // we might have cold signed, and have a mapping to key images
              std::unordered_map<crypto::public_key, crypto::key_image>::const_iterator i = m_cold_output_key_images.find(tx_scan_info[o].output_key_pair.pub);
              if (i != m_cold_output_key_images.end())
              {
                td.m_output_key_image = i->second;
                td.m_output_key_image_known = true;
              }
            }
            {
              td.m_output_key_image_request = false;
            }
            td.m_amount = amount;
            td.m_pk_index = 0;
            td.m_subaddr_index = tx_scan_info[o].received->index;
            if (should_expand(tx_scan_info[o].received->index))
              expand_subaddresses(tx_scan_info[o].received->index);
            if (tx.vout[o].amount == 0)
            {
              td.m_mask = tx_scan_info[o].mask;
              td.m_rct = true;
            }
            else if (miner_tx && tx.version == 2)
            {
              td.m_mask = rct::s_one;
              td.m_rct = true;
            }
            else
            {
              td.m_mask = rct::s_one;
              td.m_rct = false;
            }
            td.m_frozen = false;
	    set_unspent(m_transfers.size()-1);
            if (td.m_output_key_image_known)
	      m_output_key_images[td.m_output_key_image] = m_transfers.size()-1;
	    m_pub_keys[tx_scan_info[o].output_key_pair.pub] = m_transfers.size()-1;
	    LOG_VERBOSE("Received money: " << print_money(td.amount()) << ", with tx: " << txid);
	    if (0 != m_callback)
	      m_callback->on_money_received(height, txid, tx, td.m_amount, td.m_subaddr_index, spends_one_of_ours(tx), td.m_tx.unlock_height);
          }
          total_received_1 += amount;
        }
	else if (m_transfers[kit->second].m_spent || m_transfers[kit->second].amount() >= tx_scan_info[o].amount)
        {
	  LOG_ERROR("Public key " << epee::string_tools::pod_to_hex(kit->first)
              << " from received " << print_money(tx_scan_info[o].amount) << " output already exists with "
              << (m_transfers[kit->second].m_spent ? "spent" : "unspent") << " "
              << print_money(m_transfers[kit->second].amount()) << " in tx " << m_transfers[kit->second].m_txid << ", received output ignored");
          THROW_WALLET_EXCEPTION_IF(tx_money_got_in_outs[tx_scan_info[o].received->index] < tx_scan_info[o].amount,
              error::wallet_internal_error, "Unexpected values of new and old outputs");
          tx_money_got_in_outs[tx_scan_info[o].received->index] -= tx_scan_info[o].amount;

          amounts_container& tx_amounts_this_out = tx_amounts_individual_outs[tx_scan_info[o].received->index]; // Only for readability on the following lines
          auto amount_iterator = std::find(tx_amounts_this_out.begin(), tx_amounts_this_out.end(), tx_scan_info[o].amount);
          THROW_WALLET_EXCEPTION_IF(amount_iterator == tx_amounts_this_out.end(),
              error::wallet_internal_error, "Unexpected values of new and old outputs");
          tx_amounts_this_out.erase(amount_iterator);
        }
        else
        {
	  LOG_ERROR("Public key " << epee::string_tools::pod_to_hex(kit->first)
              << " from received " << print_money(tx_scan_info[o].amount) << " output already exists with "
              << print_money(m_transfers[kit->second].amount()) << ", replacing with new output");
          // The new larger output replaced a previous smaller one
          THROW_WALLET_EXCEPTION_IF(tx_money_got_in_outs[tx_scan_info[o].received->index] < tx_scan_info[o].amount,
              error::wallet_internal_error, "Unexpected values of new and old outputs");
          THROW_WALLET_EXCEPTION_IF(m_transfers[kit->second].amount() > tx_scan_info[o].amount,
              error::wallet_internal_error, "Unexpected values of new and old outputs");
          tx_money_got_in_outs[tx_scan_info[o].received->index] -= m_transfers[kit->second].amount();

          uint64_t amount = tx.vout[o].amount ? tx.vout[o].amount : tx_scan_info[o].amount;
          uint64_t extra_amount = amount - m_transfers[kit->second].amount();
          if (!pool)
          {
            transfer_details &td = m_transfers[kit->second];
	    td.m_block_height = height;
	    td.m_internal_output_index = o;
	    td.m_global_output_index = o_indices[o];
	    td.m_tx = (const cryptonote::transaction_prefix&)tx;
	    td.m_txid = txid;
            td.m_amount = amount;
            td.m_pk_index = 0;
            td.m_subaddr_index = tx_scan_info[o].received->index;
            if (should_expand(tx_scan_info[o].received->index))
              expand_subaddresses(tx_scan_info[o].received->index);
            if (tx.vout[o].amount == 0)
            {
              td.m_mask = tx_scan_info[o].mask;
              td.m_rct = true;
            }
            else if (miner_tx && tx.version == 2)
            {
              td.m_mask = rct::s_one;
              td.m_rct = true;
            }
            else
            {
              td.m_mask = rct::s_one;
              td.m_rct = false;
            }
            THROW_WALLET_EXCEPTION_IF(td.get_public_key() != tx_scan_info[o].output_key_pair.pub, error::wallet_internal_error, "Inconsistent public keys");
	    THROW_WALLET_EXCEPTION_IF(td.m_spent, error::wallet_internal_error, "Inconsistent spent status");

	    LOG_PRINT_L0("Received money: " << print_money(td.amount()) << ", with tx: " << txid);
	    if (0 != m_callback)
	      m_callback->on_money_received(height, txid, tx, td.m_amount, td.m_subaddr_index, spends_one_of_ours(tx), td.m_tx.unlock_height);
          }
          total_received_1 += extra_amount;
        }
      }
    }
  }

  THROW_WALLET_EXCEPTION_IF(tx_money_got_in_outs.size() != tx_amounts_individual_outs.size(), error::wallet_internal_error, "Inconsistent size of output arrays");

  uint64_t tx_money_spent_in_ins = 0;
  // The line below is equivalent to "std::optional<uint32_t> subaddr_account;", but avoids the GCC warning: ‘*((void*)& subaddr_account +4)’ may be used uninitialized in this function
  // It's a GCC bug with std::optional, see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=47679
  auto subaddr_account ([]()->std::optional<uint32_t> {return std::nullopt;}());
  std::set<uint32_t> subaddr_indices;
  // check all outputs for spending (compare key images)
  for(auto& in: tx.vin)
  {
    if(in.type() != typeid(cryptonote::txin_from_key))
      continue;
    const cryptonote::txin_from_key &in_to_key = boost::get<cryptonote::txin_from_key>(in);
    auto it = m_output_key_images.find(in_to_key.output_key_image);
    if(it != m_output_key_images.end())
    {
      transfer_details& td = m_transfers[it->second];
      uint64_t amount = in_to_key.amount;
      if (amount > 0)
      {
        if(amount != td.amount())
        {
          LOG_ERROR("Inconsistent amount in tx input: got " << print_money(amount) <<
            ", expected " << print_money(td.amount()));
          // this means:
          //   1) the same output pub key was used as destination multiple times,
          //   2) the wallet set the highest amount among them to transfer_details::m_amount, and
          //   3) the wallet somehow spent that output with an amount smaller than the above amount, causing inconsistency
          td.m_amount = amount;
        }
      }
      else
      {
        amount = td.amount();
      }
      tx_money_spent_in_ins += amount;
      if (subaddr_account && *subaddr_account != td.m_subaddr_index.major)
        LOG_ERROR("spent funds are from different subaddress accounts; count of incoming/outgoing payments will be incorrect");
      subaddr_account = td.m_subaddr_index.major;
      subaddr_indices.insert(td.m_subaddr_index.minor);
      if (!pool)
      {
        LOG_VERBOSE("Spent money: " << print_money(amount) << ", with tx: " << txid);
        set_spent(it->second, height);
        if (0 != m_callback)
          m_callback->on_money_spent(height, txid, tx, amount, tx, td.m_subaddr_index);
      }
    }
  }

  uint64_t fee = miner_tx ? 0 : tx.ringct.fee;

  if (tx_money_spent_in_ins > 0 && !pool)
  {
    uint64_t self_received = std::accumulate<decltype(tx_money_got_in_outs.begin()), uint64_t>(tx_money_got_in_outs.begin(), tx_money_got_in_outs.end(), 0,
      [&subaddr_account] (uint64_t acc, const std::pair<cryptonote::subaddress_index, uint64_t>& p)
      {
        return acc + (p.first.major == *subaddr_account ? p.second : 0);
      });
    process_outgoing(txid, tx, height, ts, tx_money_spent_in_ins, self_received, *subaddr_account, subaddr_indices);
    // if sending to yourself at the same subaddress account, set the outgoing payment amount to 0 so that it's less confusing
    if (tx_money_spent_in_ins == self_received + fee)
    {
      auto i = m_confirmed_txs.find(txid);
      THROW_WALLET_EXCEPTION_IF(i == m_confirmed_txs.end(), error::wallet_internal_error,
        "confirmed tx wasn't found: " + epee::string_tools::pod_to_hex(txid));
      i->second.m_change = self_received;
    }
  }

  // remove change sent to the spending subaddress account from the list of received funds
  uint64_t sub_change = 0;
  for (auto i = tx_money_got_in_outs.begin(); i != tx_money_got_in_outs.end();)
  {
    if (subaddr_account && i->first.major == *subaddr_account)
    {
      sub_change += i->second;
      tx_amounts_individual_outs.erase(i->first);
      i = tx_money_got_in_outs.erase(i);
    }
    else
      ++i;
  }

  // create payment_details for each incoming transfer to a subaddress index
  if (tx_money_got_in_outs.size() > 0)
  {
    uint64_t total_received_2 = sub_change;
    for (const auto& i : tx_money_got_in_outs)
      total_received_2 += i.second;
    if (total_received_1 != total_received_2)
    {
      const el::Level level = el::Level::Warning;
      LOG_CATEGORY_RED(level, "global", "**********************************************************************");
      LOG_CATEGORY_RED(level, "global", "Consistency failure in amounts received");
      LOG_CATEGORY_RED(level, "global", "Check transaction " << txid);
      LOG_CATEGORY_RED(level, "global", "**********************************************************************");
      exit(1);
      return;
    }

    for (const auto& i : tx_money_got_in_outs)
    {
      payment_details payment;
      payment.m_tx_hash      = txid;
      payment.m_fee          = fee;
      payment.m_amount       = i.second;
      payment.m_amounts      = tx_amounts_individual_outs[i.first];
      payment.m_block_height = height;
      payment.m_unlock_height  = tx.unlock_height;
      payment.m_timestamp    = ts;
      payment.m_coinbase     = miner_tx;
      payment.m_subaddr_index = i.first;
      if (pool) {
        if (emplace_or_replace(m_unconfirmed_payments, pool_payment_details{payment, double_spend_seen}))
        if (0 != m_callback)
          m_callback->on_unconfirmed_money_received(height, txid, tx, payment.m_amount, payment.m_subaddr_index);
      }
      else
        m_payments.emplace(crypto::null_hash, payment);
      LOG_PRINT_L2("Payment found in " << (pool ? "pool" : "block") << " / " << payment.m_tx_hash << " / " << payment.m_amount);
    }
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::process_unconfirmed(const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t height)
{
  if (m_unconfirmed_txs.empty())
    return;

  auto unconf_it = m_unconfirmed_txs.find(txid);
  if(unconf_it != m_unconfirmed_txs.end()) {
    if (store_tx_info()) {
      try {
        m_confirmed_txs.insert(std::make_pair(txid, confirmed_transfer_details(unconf_it->second, height)));
      }
      catch (...) {
        // can fail if the tx has unexpected input types
        LOG_PRINT_L0("Failed to add outgoing transaction to confirmed transaction map");
      }
    }
    m_unconfirmed_txs.erase(unconf_it);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::process_outgoing(const crypto::hash &txid, const cryptonote::transaction &tx, uint64_t height, uint64_t ts, uint64_t spent, uint64_t received, uint32_t subaddr_account, const std::set<uint32_t>& subaddr_indices)
{
  std::pair<std::unordered_map<crypto::hash, confirmed_transfer_details>::iterator, bool> entry = m_confirmed_txs.insert(std::make_pair(txid, confirmed_transfer_details()));
  // fill with the info we know, some info might already be there
  if (entry.second)
  {
    // this case will happen if the tx is from our outputs, but was sent by another
    // wallet (eg, we're a cold wallet and the hot wallet sent it). For RCT transactions,
    // we only see 0 input amounts, so have to deduce amount out from other parameters.
    entry.first->second.m_amount_in = spent;
    entry.first->second.m_amount_out = spent - tx.ringct.fee;
    entry.first->second.m_change = received;

    entry.first->second.m_subaddr_account = subaddr_account;
    entry.first->second.m_subaddr_indices = subaddr_indices;
  }

  entry.first->second.m_rings.clear();
  for (const auto &in: tx.vin)
  {
    if (in.type() != typeid(cryptonote::txin_from_key))
      continue;
    const auto &txin = boost::get<cryptonote::txin_from_key>(in);
    entry.first->second.m_rings.push_back(std::make_pair(txin.output_key_image, txin.output_relative_offsets));
  }
  entry.first->second.m_block_height = height;
  entry.first->second.m_timestamp = ts;
  entry.first->second.m_unlock_height = tx.unlock_height;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::should_skip_block(const cryptonote::block &b, uint64_t height) const
{
  // seeking only for blocks that are not older then the wallet creation time plus 1 day. 1 day is for possible user incorrect time setup
  return !(b.timestamp + 60*60*24 > m_account.get_createtime() && height >= m_refresh_from_block_height);
}
//----------------------------------------------------------------------------------------------------
void wallet2::process_new_blockchain_entry
(
 const cryptonote::block& b
 , const cryptonote::block_complete_entry& bche
 , const parsed_block &parsed_block
 , const crypto::hash& bl_id
 , uint64_t height
 )
{
  THROW_WALLET_EXCEPTION_IF(bche.txs.size() + 1 != parsed_block.o_indices.indices.size(), error::wallet_internal_error,
      "block transactions=" + std::to_string(bche.txs.size()) +
      " not match with daemon response size=" + std::to_string(parsed_block.o_indices.indices.size()));

  //handle transactions from new block

  //optimization: seeking only for blocks that are not older then the wallet creation time plus 1 day. 1 day is for possible user incorrect time setup
  if (!should_skip_block(b, height))
  {
    process_new_transaction
      (
       get_transaction_hash(b.miner_tx)
       , b.miner_tx
       , parsed_block.o_indices.indices[0].indices
       , height
       , b.major_version
       , b.timestamp
       , true
       , false
       , false
       );

    THROW_WALLET_EXCEPTION_IF(bche.txs.size() != b.tx_hashes.size(), error::wallet_internal_error, "Wrong amount of transactions for block");
    THROW_WALLET_EXCEPTION_IF(bche.txs.size() != parsed_block.txes.size(), error::wallet_internal_error, "Wrong amount of transactions for block");

    for (size_t idx = 0; idx < b.tx_hashes.size(); ++idx)
    {
      process_new_transaction
        (
         b.tx_hashes[idx]
         , parsed_block.txes[idx]
         , parsed_block.o_indices.indices[idx+1].indices
         , height
         , b.major_version
         , b.timestamp
         , false
         , false
         , false
         );
    }
  }
  else
  {
    if (!(height % 128))
      LOG_PRINT_L2( "Skipped block by timestamp, height: " << height << ", block time " << b.timestamp << ", account time " << m_account.get_createtime());
  }

  m_blockchain.push_back(bl_id);

  if (0 != m_callback)
    m_callback->on_new_block(height, b);
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_short_chain_history(std::list<crypto::hash>& ids) const
{
  size_t i = 0;
  size_t current_multiplier = 1;
  size_t sz = m_blockchain.size() - m_blockchain.offset();
  if(!sz)
  {
    ids.push_back(m_blockchain.genesis());
    return;
  }
  size_t current_back_offset = 1;
  bool base_included = false;
  while(current_back_offset < sz)
  {
    ids.push_back(m_blockchain[m_blockchain.offset() + sz-current_back_offset]);
    if(sz-current_back_offset == 0)
      base_included = true;
    if(i < 10)
    {
      ++current_back_offset;
    }else
    {
      current_back_offset += current_multiplier *= 2;
    }
    ++i;
  }
  if(!base_included)
    ids.push_back(m_blockchain[m_blockchain.offset()]);
  if(m_blockchain.offset())
    ids.push_back(m_blockchain.genesis());
}
//----------------------------------------------------------------------------------------------------
void wallet2::parse_block_round(const cryptonote::string_blob &blob, cryptonote::block &bl, crypto::hash &bl_id, bool &error) const
{
  const auto r = maybe_block_and_hash_from_blob(blob);
  if (r) {
    std::tie(bl, bl_id) = *r;
  }
  error = !r;
}
//----------------------------------------------------------------------------------------------------
void wallet2::pull_blocks(uint64_t start_height, uint64_t &blocks_start_height, const std::list<crypto::hash> &short_chain_history, std::vector<cryptonote::block_complete_entry> &blocks, std::vector<cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::block_output_indices> &o_indices, uint64_t &current_height)
{
  cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request req = AUTO_VAL_INIT(req);
  cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res = AUTO_VAL_INIT(res);
  std::list<std::string> block_ids;
  std::transform
    (
     short_chain_history.begin()
     , short_chain_history.end()
     , std::back_inserter(block_ids)
     , [](const auto& x) { return epee::string_tools::pod_to_hex(x); }
     );

  req.block_ids = block_ids;

  LOG_DEBUG("Pulling blocks: start_height " << start_height);

  req.prune = true;
  req.start_height = start_height;
  req.no_miner_tx = false;

  {
    bool r = m_rpc_client.invoke_http_json("/get_blocks", req, res);
    THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "get_blocks", error::get_blocks_error, (res.status));
    THROW_WALLET_EXCEPTION_IF(res.blocks.size() != res.output_indices.size(), error::wallet_internal_error,
        "mismatched blocks (" + boost::lexical_cast<std::string>(res.blocks.size()) + ") and output_indices (" +
        boost::lexical_cast<std::string>(res.output_indices.size()) + ") sizes from daemon");
  }

  blocks_start_height = res.start_height;
  blocks = std::move(res.blocks);
  o_indices = std::move(res.output_indices);
  current_height = res.current_height;

  LOG_DEBUG("Pulled blocks: blocks_start_height " << blocks_start_height << ", count " << blocks.size()
      << ", height " << blocks_start_height + blocks.size() << ", node height " << res.current_height);
}
//----------------------------------------------------------------------------------------------------
void wallet2::pull_hashes(uint64_t start_height, uint64_t &blocks_start_height, const std::list<crypto::hash> &short_chain_history, std::vector<crypto::hash> &hashes)
{
  cryptonote::COMMAND_RPC_GET_HASHES_FAST::request req = AUTO_VAL_INIT(req);
  cryptonote::COMMAND_RPC_GET_HASHES_FAST::response res = AUTO_VAL_INIT(res);

  std::list<std::string> block_ids;
  std::transform
    (
     short_chain_history.begin()
     , short_chain_history.end()
     , std::back_inserter(block_ids)
     , [](const auto& x) { return epee::string_tools::pod_to_hex(x); }
     );

  req.block_ids = block_ids;

  req.start_height = start_height;

  {
    bool r = m_rpc_client.invoke_http_json("/get_hashes", req, res);
    THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "get_hashes", error::get_hashes_error, (res.status));
  }

  blocks_start_height = res.start_height;
  hashes.clear();
  std::transform
    (
     res.m_block_ids.begin()
     , res.m_block_ids.end()
     , std::back_inserter(hashes)
     , [](const auto& x) {
       const auto maybe_hash =
         epee::string_tools::hex_to_pod<crypto::hash>(x);

      if (!maybe_hash) {
        LOG_FATAL("invalid block id hash");
      }

       return maybe_hash.value_or(crypto::null_hash);
     }
     );
}
//----------------------------------------------------------------------------------------------------
void wallet2::process_parsed_blocks(uint64_t start_height, const std::vector<cryptonote::block_complete_entry> &blocks, const std::vector<parsed_block> &parsed_blocks, uint64_t& blocks_added)
{
  size_t current_index = start_height;
  blocks_added = 0;

  THROW_WALLET_EXCEPTION_IF(blocks.size() != parsed_blocks.size(), error::wallet_internal_error, "size mismatch");
  THROW_WALLET_EXCEPTION_IF(!m_blockchain.is_in_bounds(current_index), error::out_of_hashchain_bounds_error);

  for (size_t i = 0; i < blocks.size(); ++i)
  {
    const crypto::hash &bl_id = parsed_blocks[i].hash;
    const cryptonote::block &bl = parsed_blocks[i].block;

    if(current_index >= m_blockchain.size())
    {
      process_new_blockchain_entry(bl, blocks[i], parsed_blocks[i], bl_id, current_index);
      ++blocks_added;
    }
    else if(bl_id != m_blockchain[current_index])
    {
      //split detected here !!!
      THROW_WALLET_EXCEPTION_IF(current_index == start_height, error::wallet_internal_error,
        "wrong daemon response: split starts from the first block in response " + epee::string_tools::pod_to_hex(bl_id) +
        " (height " + std::to_string(start_height) + "), local block id at this height: " +
        epee::string_tools::pod_to_hex(m_blockchain[current_index]));

      detach_blockchain(current_index);
      process_new_blockchain_entry(bl, blocks[i], parsed_blocks[i], bl_id, current_index);
    }
    else
    {
      LOG_DEBUG("Block is already in blockchain: " << epee::string_tools::pod_to_hex(bl_id));
    }
    ++current_index;
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::refresh()
{
  uint64_t blocks_fetched = 0;
  refresh(0, blocks_fetched);
}
//----------------------------------------------------------------------------------------------------
void wallet2::refresh(uint64_t start_height, uint64_t & blocks_fetched)
{
  bool received_money = false;
  refresh(start_height, blocks_fetched, received_money);
}
//----------------------------------------------------------------------------------------------------
void wallet2::pull_and_parse_next_blocks(uint64_t start_height, uint64_t &blocks_start_height, std::list<crypto::hash> &short_chain_history, const std::vector<cryptonote::block_complete_entry> &prev_blocks, const std::vector<parsed_block> &prev_parsed_blocks, std::vector<cryptonote::block_complete_entry> &blocks, std::vector<parsed_block> &parsed_blocks, bool &last, bool &error, std::exception_ptr &exception)
{
  error = false;
  last = false;
  exception = NULL;

  try
  {
    drop_from_short_history(short_chain_history, config::lol::reorg_buffer);

    THROW_WALLET_EXCEPTION_IF(prev_blocks.size() != prev_parsed_blocks.size(), error::wallet_internal_error, "size mismatch");

    // prepend the last reorg_buffer blocks, should be enough to guard against a block or two's reorg
    auto s = std::next(prev_parsed_blocks.rbegin(), std::min(config::lol::reorg_buffer, prev_parsed_blocks.size())).base();
    for (; s != prev_parsed_blocks.end(); ++s)
    {
      short_chain_history.push_front(s->hash);
    }

    // pull the new blocks
    std::vector<cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::block_output_indices> o_indices;
    uint64_t current_height;
    pull_blocks(start_height, blocks_start_height, short_chain_history, blocks, o_indices, current_height);
    THROW_WALLET_EXCEPTION_IF(blocks.size() != o_indices.size(), error::wallet_internal_error, "Mismatched sizes of blocks and o_indices");

    tools::threadpool& tpool = tools::threadpool::getInstance();
    tools::threadpool::waiter waiter(tpool);
    parsed_blocks.resize(blocks.size());
    for (size_t i = 0; i < blocks.size(); ++i)
    {
      tpool.submit(&waiter, std::bind(&wallet2::parse_block_round, this, std::cref(blocks[i].block),
        std::ref(parsed_blocks[i].block), std::ref(parsed_blocks[i].hash), std::ref(parsed_blocks[i].error)), true);
    }
    THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");
    for (size_t i = 0; i < blocks.size(); ++i)
    {
      if (parsed_blocks[i].error)
      {
        error = true;
        break;
      }
      parsed_blocks[i].o_indices = std::move(o_indices[i]);
    }

    std::mutex error_lock;
    for (size_t i = 0; i < blocks.size(); ++i)
    {
      parsed_blocks[i].txes.resize(blocks[i].txs.size());
      for (size_t j = 0; j < blocks[i].txs.size(); ++j)
      {
        tpool.submit(&waiter, [&, i, j](){
          const auto maybeTx = maybe_tx_from_blob(blocks[i].txs[j].blob);
          if (!maybeTx)
          {
            std::unique_lock<std::mutex> lock(error_lock);
            error = true;
          }
          parsed_blocks[i].txes[j] = *maybeTx;
        }, true);
      }
    }
    THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");
    last = !blocks.empty() && cryptonote::get_block_height(parsed_blocks.back().block) + 1 == current_height;
  }
  catch(...)
  {
    error = true;
    exception = std::current_exception();
  }
}

void wallet2::remove_obsolete_pool_txs(const std::vector<crypto::hash> &tx_hashes)
{
  // remove pool txes to us that aren't in the pool anymore
  std::unordered_multimap<crypto::hash, wallet::logic::type::payment::pool_payment_details>::iterator uit = m_unconfirmed_payments.begin();
  while (uit != m_unconfirmed_payments.end())
  {
    const crypto::hash &txid = uit->second.m_pd.m_tx_hash;
    bool found = false;
    for (const auto &it2: tx_hashes)
    {
      if (it2 == txid)
      {
        found = true;
        break;
      }
    }
    auto pit = uit++;
    if (!found)
    {
      LOG_DEBUG("Removing " << txid << " from unconfirmed payments, not found in pool");
      m_unconfirmed_payments.erase(pit);
      if (0 != m_callback)
        m_callback->on_pool_tx_removed(txid);
    }
  }
}

//----------------------------------------------------------------------------------------------------
void wallet2::update_pool_state(std::vector<std::tuple<cryptonote::transaction, crypto::hash, bool>> &process_txs, bool refreshed)
{
  LOG_TRACE("update_pool_state start");

  // get the pool state
  cryptonote::COMMAND_RPC_GET_TRANSACTION_POOL_HASHES::request req;
  cryptonote::COMMAND_RPC_GET_TRANSACTION_POOL_HASHES::response res;

  {
    bool r = m_rpc_client.invoke_http_json("/get_transaction_pool_hashes", req, res);
    THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "get_transaction_pool_hashes", error::get_tx_pool_error);
  }
  LOG_TRACE("update_pool_state got pool");

  std::vector<crypto::hash> tx_hashes;
  std::transform
    (
     res.tx_hashes.begin()
     , res.tx_hashes.end()
     , std::back_inserter(tx_hashes)
     , [](const auto& x) {
       return parse_hash256(x).value_or(crypto::null_hash);
     }
     );

  // remove any pending tx that's not in the pool
  std::unordered_map<crypto::hash, wallet::logic::type::transfer::unconfirmed_transfer_details>::iterator it = m_unconfirmed_txs.begin();
  while (it != m_unconfirmed_txs.end())
  {
    const crypto::hash &txid = it->first;
    bool found = false;
    for (const auto &it2: tx_hashes)
    {
      if (it2 == txid)
      {
        found = true;
        break;
      }
    }
    auto pit = it++;
    if (!found)
    {
      // we want to avoid a false positive when we ask for the pool just after
      // a tx is removed from the pool due to being found in a new block, but
      // just before the block is visible by refresh. So we keep a boolean, so
      // that the first time we don't see the tx, we set that boolean, and only
      // delete it the second time it is checked (but only when refreshed, so
      // we're sure we've seen the blockchain state first)
      if (pit->second.m_state == wallet::logic::type::transfer::unconfirmed_transfer_details::pending)
      {
        LOG_PRINT_L1("Pending txid " << txid << " not in pool, marking as not in pool");
        pit->second.m_state = wallet::logic::type::transfer::unconfirmed_transfer_details::pending_not_in_pool;
      }
      else if (pit->second.m_state == wallet::logic::type::transfer::unconfirmed_transfer_details::pending_not_in_pool && refreshed)
      {
        LOG_PRINT_L1("Pending txid " << txid << " not in pool, marking as failed");
        pit->second.m_state = wallet::logic::type::transfer::unconfirmed_transfer_details::failed;

        // the inputs aren't spent anymore, since the tx failed
        for (size_t vini = 0; vini < pit->second.m_tx.vin.size(); ++vini)
        {
          if (pit->second.m_tx.vin[vini].type() == typeid(txin_from_key))
          {
            txin_from_key &tx_in_to_key = boost::get<txin_from_key>(pit->second.m_tx.vin[vini]);
            for (size_t i = 0; i < m_transfers.size(); ++i)
            {
              const transfer_details &td = m_transfers[i];
              if (td.m_output_key_image == tx_in_to_key.output_key_image)
              {
                 LOG_PRINT_L1("Resetting spent status for output " << vini << ": " << td.m_output_key_image);
                 set_unspent(i);
                 break;
              }
            }
          }
        }
      }
    }
  }
  LOG_TRACE("update_pool_state done first loop");

  // remove pool txes to us that aren't in the pool anymore
  // but only if we just refreshed, so that the tx can go in
  // the in transfers list instead (or nowhere if it just
  // disappeared without being mined)
  if (refreshed)
    remove_obsolete_pool_txs(tx_hashes);

  LOG_TRACE("update_pool_state done second loop");

  // gather txids of new pool txes to us
  std::vector<std::pair<crypto::hash, bool>> txids;
  for (const auto &txid: tx_hashes)
  {
    bool txid_found_in_up = false;
    for (const auto &up: m_unconfirmed_payments)
    {
      if (up.second.m_pd.m_tx_hash == txid)
      {
        txid_found_in_up = true;
        break;
      }
    }
    if (m_scanned_pool_txs[0].find(txid) != m_scanned_pool_txs[0].end() || m_scanned_pool_txs[1].find(txid) != m_scanned_pool_txs[1].end())
    {
      // if it's for us, we want to keep track of whether we saw a double spend, so don't bail out
      if (!txid_found_in_up)
      {
        LOG_PRINT_L2("Already seen " << txid << ", and not for us, skipped");
        continue;
      }
    }
    if (!txid_found_in_up)
    {
      LOG_PRINT_L1("Found new pool tx: " << txid);
      bool found = false;
      for (const auto &i: m_unconfirmed_txs)
      {
        if (i.first == txid)
        {
          found = true;
          // if this is a payment to yourself at a different subaddress account, don't skip it
          // so that you can see the incoming pool tx with 'show' on that receiving subaddress account
          const unconfirmed_transfer_details& utd = i.second;
          for (const auto& dst : utd.m_dests)
          {
            auto subaddr_index = m_subaddresses.find(dst.addr.m_spend_public_key);
            if (subaddr_index != m_subaddresses.end() && subaddr_index->second.major != utd.m_subaddr_account)
            {
              found = false;
              break;
            }
          }
          break;
        }
      }
      if (!found)
      {
        // not one of those we sent ourselves
        txids.push_back({txid, false});
      }
      else
      {
        LOG_PRINT_L1("We sent that one");
      }
    }
  }

  // get those txes
  if (!txids.empty())
  {
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request req;
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response res;
    for (const auto &p: txids)
      req.txs_hashes.push_back(epee::string_tools::pod_to_hex(p.first));
    LOG_DEBUG("asking for " << txids.size() << " transactions");
    req.decode_as_json = false;
    req.prune = true;

    bool r;
    {
      r = m_rpc_client.invoke_http_json("/get_transactions", req, res);
    }

    LOG_DEBUG("Got " << r << " and " << res.status);
    if (r && res.status == CORE_RPC_STATUS_OK)
    {
      if (res.txs.size() == txids.size())
      {
        for (const auto &tx_entry: res.txs)
        {
          if (tx_entry.in_pool)
          {
            cryptonote::transaction tx;
            cryptonote::string_blob bd;
            crypto::hash tx_hash;

            if (get_full_tx(tx_entry, tx, tx_hash))
            {
                const std::vector<std::pair<crypto::hash, bool>>::const_iterator i = std::find_if(txids.begin(), txids.end(),
                    [tx_hash](const std::pair<crypto::hash, bool> &e) { return e.first == tx_hash; });
                if (i != txids.end())
                {
                  process_txs.push_back(std::make_tuple(tx, tx_hash, tx_entry.double_spend_seen));
                }
                else
                {
                  LOG_ERROR("Got txid " << tx_hash << " which we did not ask for");
                }
            }
            else
            {
              LOG_PRINT_L0("Failed to parse transaction from daemon");
            }
          }
          else
          {
            LOG_PRINT_L1("Transaction from daemon was in pool, but is no more");
          }
        }
      }
      else
      {
        LOG_PRINT_L0("Expected " << txids.size() << " tx(es), got " << res.txs.size());
      }
    }
    else
    {
      LOG_PRINT_L0("Error calling gettransactions daemon RPC: r " << r << ", status " << (res.status));
    }
  }
  LOG_TRACE("update_pool_state end");
}
//----------------------------------------------------------------------------------------------------
void wallet2::process_pool_state(const std::vector<std::tuple<cryptonote::transaction, crypto::hash, bool>> &txs)
{
  const time_t now = time(NULL);
  for (const auto &e: txs)
  {
    const cryptonote::transaction &tx = std::get<0>(e);
    const crypto::hash &tx_hash = std::get<1>(e);
    const bool double_spend_seen = std::get<2>(e);
    process_new_transaction(tx_hash, tx, std::vector<uint64_t>(), 0, 0, now, false, true, double_spend_seen);
    m_scanned_pool_txs[0].insert(tx_hash);
    if (m_scanned_pool_txs[0].size() > 5000)
    {
      std::swap(m_scanned_pool_txs[0], m_scanned_pool_txs[1]);
      m_scanned_pool_txs[0].clear();
    }
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::fast_refresh(uint64_t stop_height, uint64_t &blocks_start_height, std::list<crypto::hash> &short_chain_history, bool force)
{
  std::vector<crypto::hash> hashes;

  size_t current_index = m_blockchain.size();
  while(m_run && current_index < stop_height)
  {
    pull_hashes(0, blocks_start_height, short_chain_history, hashes);
    if (hashes.size() <= config::lol::reorg_buffer)
      return;
    if (blocks_start_height < m_blockchain.offset())
    {
      LOG_ERROR("Blocks start before blockchain offset: " << blocks_start_height << " " << m_blockchain.offset());
      return;
    }
    current_index = blocks_start_height;
    if (hashes.size() + current_index < stop_height) {
      drop_from_short_history(short_chain_history, config::lol::reorg_buffer);
      std::vector<crypto::hash>::iterator right = hashes.end();
      // prepend reorg_buffer more
      for (int i = 0; i< config::lol::reorg_buffer; i++) {
        right--;
        short_chain_history.push_front(*right);
      }
    }
    for(auto& bl_id: hashes)
    {
      if(current_index >= m_blockchain.size())
      {
        if (!(current_index % 1024))
          LOG_PRINT_L2( "Skipped block by height: " << current_index);
        m_blockchain.push_back(bl_id);

        if (0 != m_callback)
        { // FIXME: this isn't right, but simplewallet just logs that we got a block.
          cryptonote::block dummy;
          m_callback->on_new_block(current_index, dummy);
        }
      }
      else if(bl_id != m_blockchain[current_index])
      {
        //split detected here !!!
        return;
      }
      ++current_index;
      if (current_index >= stop_height)
        return;
    }
  }
}


//----------------------------------------------------------------------------------------------------
void wallet2::refresh(uint64_t start_height, uint64_t & blocks_fetched, bool& received_money, bool check_pool)
{
  if (m_offline)
  {
    blocks_fetched = 0;
    received_money = 0;
    return;
  }

  received_money = false;
  blocks_fetched = 0;
  uint64_t added_blocks = 0;
  size_t try_count = 0;
  crypto::hash last_tx_hash_id = m_transfers.size() ? m_transfers.back().m_txid : crypto::null_hash;
  std::list<crypto::hash> short_chain_history;
  tools::threadpool& tpool = tools::threadpool::getInstance();
  tools::threadpool::waiter waiter(tpool);
  uint64_t blocks_start_height;
  std::vector<cryptonote::block_complete_entry> blocks;
  std::vector<parsed_block> parsed_blocks;

  // pull the first set of blocks
  get_short_chain_history(short_chain_history);
  m_run = true;
  if (start_height > m_blockchain.size() || m_refresh_from_block_height > m_blockchain.size()) {
    if (!start_height)
      start_height = m_refresh_from_block_height;
    // we can shortcut by only pulling hashes up to the start_height
    fast_refresh(start_height, blocks_start_height, short_chain_history);
    // regenerate the history now that we've got a full set of hashes
    short_chain_history.clear();
    get_short_chain_history(short_chain_history);
    start_height = 0;
    // and then fall through to regular refresh processing
  }

  // If stop() is called during fast refresh we don't need to continue
  if(!m_run)
    return;
  // always reset start_height to 0 to force short_chain_ history to be used on
  // subsequent pulls in this refresh.
  start_height = 0;

  // get updated pool state first, but do not process those txes just yet,
  // since that might cause a password prompt, which would introduce a data
  // leak allowing a passive adversary with traffic analysis capability to
  // infer when we get an incoming output
  std::vector<std::tuple<cryptonote::transaction, crypto::hash, bool>> process_pool_txs;
  update_pool_state(process_pool_txs, true);

  bool first = true, last = false;
  while(m_run)
  {
    uint64_t next_blocks_start_height;
    std::vector<cryptonote::block_complete_entry> next_blocks;
    std::vector<parsed_block> next_parsed_blocks;
    bool error;
    std::exception_ptr exception;
    try
    {
      // pull the next set of blocks while we're processing the current one
      error = false;
      exception = NULL;
      next_blocks.clear();
      next_parsed_blocks.clear();
      added_blocks = 0;
      if (!first && blocks.empty())
      {
        // m_rpc_client.set_height(m_blockchain.size());
        break;
      }
      if (!last)
        tpool.submit(&waiter, [&]{pull_and_parse_next_blocks(start_height, next_blocks_start_height, short_chain_history, blocks, parsed_blocks, next_blocks, next_parsed_blocks, last, error, exception);});

      if (!first)
      {
        try
        {
          process_parsed_blocks(blocks_start_height, blocks, parsed_blocks, added_blocks);
        }
        catch (const tools::error::out_of_hashchain_bounds_error&)
        {
          LOG_INFO("Daemon claims next refresh block is out of hash chain bounds, resetting hash chain");
          uint64_t stop_height = m_blockchain.offset();
          std::vector<crypto::hash> tip(m_blockchain.size() - m_blockchain.offset());
          for (size_t i = m_blockchain.offset(); i < m_blockchain.size(); ++i)
            tip[i - m_blockchain.offset()] = m_blockchain[i];
          cryptonote::block b;
          generate_genesis(b);
          m_blockchain.clear();
          m_blockchain.push_back(get_block_hash(b));
          short_chain_history.clear();
          get_short_chain_history(short_chain_history);
          fast_refresh(stop_height, blocks_start_height, short_chain_history, true);
          THROW_WALLET_EXCEPTION_IF((m_blockchain.size() == stop_height || (m_blockchain.size() == 1 && stop_height == 0) ? false : true), error::wallet_internal_error, "Unexpected hashchain size");
          THROW_WALLET_EXCEPTION_IF(m_blockchain.offset() != 0, error::wallet_internal_error, "Unexpected hashchain offset");
          for (const auto &h: tip)
            m_blockchain.push_back(h);
          short_chain_history.clear();
          get_short_chain_history(short_chain_history);
          start_height = stop_height;
          throw std::runtime_error(""); // loop again
        }
        catch (const std::exception &e)
        {
          LOG_ERROR("Error parsing blocks: " << e.what());
          error = true;
        }
        blocks_fetched += added_blocks;
      }
      THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");
      if(!first && blocks_start_height == next_blocks_start_height)
      {
        // m_rpc_client.set_height(m_blockchain.size());
        break;
      }

      first = false;

      // handle error from async fetching thread
      if (error)
      {
        if (exception)
          std::rethrow_exception(exception);
        else
          throw std::runtime_error("proxy exception in refresh thread");
      }

      // switch to the new blocks from the daemon
      blocks_start_height = next_blocks_start_height;
      blocks = std::move(next_blocks);
      parsed_blocks = std::move(next_parsed_blocks);
    }
    catch (const tools::error::password_needed&)
    {
      blocks_fetched += added_blocks;
      THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");
      throw;
    }
    catch (const std::exception&)
    {
      blocks_fetched += added_blocks;
      THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");
      if(try_count < config::lol::reorg_buffer)
      {
        LOG_PRINT_L1("Another try pull_blocks (try_count=" << try_count << ")...");
        first = true;
        start_height = 0;
        blocks.clear();
        parsed_blocks.clear();
        short_chain_history.clear();
        get_short_chain_history(short_chain_history);
        ++try_count;
      }
      else
      {
        LOG_ERROR("pull_blocks failed, try_count=" << try_count);
        throw;
      }
    }
  }
  if(last_tx_hash_id != (m_transfers.size() ? m_transfers.back().m_txid : crypto::null_hash))
    received_money = true;

  try
  {
    // If stop() is called we don't need to check pending transactions
    if (check_pool && m_run && !process_pool_txs.empty())
      process_pool_state(process_pool_txs);
  }
  catch (...)
  {
    LOG_PRINT_L1("Failed to check pending transactions");
  }

  LOG_PRINT_L1("Refresh done, blocks received: " << blocks_fetched << ", balance (all accounts): " << print_money(balance_all(false)) << ", unlocked: " << print_money(unlocked_balance_all(false)));
}
//----------------------------------------------------------------------------------------------------
bool wallet2::refresh(uint64_t & blocks_fetched, bool& received_money, bool& ok)
{
  try
  {
    refresh(0, blocks_fetched, received_money);
    ok = true;
  }
  catch (...)
  {
    ok = false;
  }
  return ok;
}
//----------------------------------------------------------------------------------------------------
void wallet2::detach_blockchain(uint64_t height)
{
  LOG_PRINT_L0("Detaching blockchain on height " << height);

  // size  1 2 3 4 5 6 7 8 9
  // block 0 1 2 3 4 5 6 7 8
  //               C
  THROW_WALLET_EXCEPTION_IF(height < m_blockchain.offset() && m_blockchain.size() > m_blockchain.offset(),
      error::wallet_internal_error, "Daemon claims reorg below last checkpoint");

  size_t transfers_detached = 0;

  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    wallet::logic::type::transfer::transfer_details &td = m_transfers[i];
    if (td.m_spent && td.m_spent_height >= height)
    {
      LOG_PRINT_L1("Resetting spent/frozen status for output " << i << ": " << td.m_output_key_image);
      set_unspent(i);
    }
  }

  for (transfer_details &td: m_transfers)
  {
    while (!td.m_uses.empty() && td.m_uses.back().first >= height)
      td.m_uses.pop_back();
  }

  auto it = std::find_if(m_transfers.begin(), m_transfers.end(), [&](const transfer_details& td){return td.m_block_height >= height;});
  size_t i_start = it - m_transfers.begin();

  for(size_t i = i_start; i!= m_transfers.size();i++)
  {
    if (!m_transfers[i].m_output_key_image_known || m_transfers[i].m_output_key_image_partial)
      continue;
    auto it_ki = m_output_key_images.find(m_transfers[i].m_output_key_image);
    THROW_WALLET_EXCEPTION_IF(it_ki == m_output_key_images.end(), error::wallet_internal_error, "key image not found: index " + std::to_string(i) + ", ki " + epee::string_tools::pod_to_hex(m_transfers[i].m_output_key_image) + ", " + std::to_string(m_output_key_images.size()) + " key images known");
    m_output_key_images.erase(it_ki);
  }

  for(size_t i = i_start; i!= m_transfers.size();i++)
  {
    auto it_pk = m_pub_keys.find(m_transfers[i].get_public_key());
    THROW_WALLET_EXCEPTION_IF(it_pk == m_pub_keys.end(), error::wallet_internal_error, "public key not found");
    m_pub_keys.erase(it_pk);
  }
  transfers_detached = std::distance(it, m_transfers.end());
  m_transfers.erase(it, m_transfers.end());

  size_t blocks_detached = m_blockchain.size() - height;
  m_blockchain.crop(height);

  for (auto it = m_payments.begin(); it != m_payments.end(); )
  {
    if(height <= it->second.m_block_height)
      it = m_payments.erase(it);
    else
      ++it;
  }

  for (auto it = m_confirmed_txs.begin(); it != m_confirmed_txs.end(); )
  {
    if(height <= it->second.m_block_height)
      it = m_confirmed_txs.erase(it);
    else
      ++it;
  }

  LOG_PRINT_L0("Detached blockchain on height " << height << ", transfers detached " << transfers_detached << ", blocks detached " << blocks_detached);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::deinit()
{
  m_is_initialized=false;
  m_account.deinit();
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::clear()
{
  m_blockchain.clear();
  m_transfers.clear();
  m_output_key_images.clear();
  m_pub_keys.clear();
  m_unconfirmed_txs.clear();
  m_payments.clear();
  m_tx_keys.clear();
  m_output_secret_keys.clear();
  m_confirmed_txs.clear();
  m_unconfirmed_payments.clear();
  m_scanned_pool_txs[0].clear();
  m_scanned_pool_txs[1].clear();
  m_subaddresses.clear();
  m_subaddress_labels.clear();
  return true;
}
//----------------------------------------------------------------------------------------------------
void wallet2::clear_soft()
{
  m_blockchain.clear();
  m_transfers.clear();
  m_output_key_images.clear();
  m_pub_keys.clear();
  m_unconfirmed_txs.clear();
  m_payments.clear();
  m_confirmed_txs.clear();
  m_unconfirmed_payments.clear();
  m_scanned_pool_txs[0].clear();
  m_scanned_pool_txs[1].clear();

  cryptonote::block b;
  generate_genesis(b);
  m_blockchain.push_back(get_block_hash(b));
}

/*!
 * \brief Stores wallet information to wallet file.
 * \param  keys_file_name Name of wallet file
 * \param  password       Password of wallet file
 * \return                Whether it was successful.
 */
bool wallet2::store_keys(const std::string& keys_file_name, const epee::wipeable_string& password)
{
  std::optional<wallet::logic::type::wallet::keys_file_data> keys_file_data = get_keys_file_data(password);
  LOG_ERROR_AND_RETURN_UNLESS(keys_file_data != std::nullopt, false, "failed to generate wallet keys data");

  std::string tmp_file_name = keys_file_name + ".new";
  std::string buf;
  bool r = ::serialization::dump_binary(keys_file_data.value(), buf);
  r = r && wallet::logic::controller::wallet::save_to_file
    (tmp_file_name, buf);
  LOG_ERROR_AND_RETURN_UNLESS(r, false, "failed to generate wallet keys file " << tmp_file_name);

  std::error_code e = tools::replace_file(tmp_file_name, keys_file_name);

  if (e) {
    std::filesystem::remove(tmp_file_name);
    LOG_ERROR("failed to update wallet keys file " << keys_file_name);
    return false;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
std::optional<wallet::logic::type::wallet::keys_file_data> wallet2::get_keys_file_data(const epee::wipeable_string& password)
{
  std::string account_data;
  cryptonote::account_base account = m_account;

  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);

  account.encrypt_keys(key);

  bool r = epee::serialization::store_t_to_binary(account, account_data);
  LOG_ERROR_AND_RETURN_UNLESS(r, std::nullopt, "failed to serialize wallet keys");
  std::optional<wallet::logic::type::wallet::keys_file_data> keys_file_data = (wallet::logic::type::wallet::keys_file_data) {};

  // Create a JSON object with "key_data" and "seed_language" as keys.
  rapidjson::Document json;
  json.SetObject();
  rapidjson::Value value(rapidjson::kStringType);
  value.SetString(account_data.c_str(), account_data.length());
  json.AddMember("key_data", value, json.GetAllocator());
  if (!seed_language.empty())
  {
    value.SetString(seed_language.c_str(), seed_language.length());
    json.AddMember("seed_language", value, json.GetAllocator());
  }

  rapidjson::Value value2(rapidjson::kNumberType);

  value2.SetInt(m_always_confirm_transfers ? 1 :0);
  json.AddMember("always_confirm_transfers", value2, json.GetAllocator());

  value2.SetInt(m_print_ring_members ? 1 :0);
  json.AddMember("print_ring_members", value2, json.GetAllocator());

  value2.SetInt(m_store_tx_info ? 1 :0);
  json.AddMember("store_tx_info", value2, json.GetAllocator());

  value2.SetUint(m_default_priority);
  json.AddMember("default_priority", value2, json.GetAllocator());

  value2.SetUint64(m_refresh_from_block_height);
  json.AddMember("refresh_height", value2, json.GetAllocator());

  value2.SetInt(m_ask_password);
  json.AddMember("ask_password", value2, json.GetAllocator());

  value2.SetInt(cryptonote::get_default_decimal_point());
  json.AddMember("default_decimal_point", value2, json.GetAllocator());

  value2.SetInt(m_merge_destinations ? 1 :0);
  json.AddMember("merge_destinations", value2, json.GetAllocator());

  value2.SetInt(m_confirm_export_overwrite ? 1 :0);
  json.AddMember("confirm_export_overwrite", value2, json.GetAllocator());

  value2.SetUint(m_nettype);
  json.AddMember("nettype", value2, json.GetAllocator());

  value2.SetInt(m_ignore_fractional_outputs ? 1 : 0);
  json.AddMember("ignore_fractional_outputs", value2, json.GetAllocator());

  value2.SetUint64(m_ignore_outputs_above);
  json.AddMember("ignore_outputs_above", value2, json.GetAllocator());

  value2.SetUint64(m_ignore_outputs_below);
  json.AddMember("ignore_outputs_below", value2, json.GetAllocator());

  value2.SetUint(m_subaddress_lookahead_major);
  json.AddMember("subaddress_lookahead_major", value2, json.GetAllocator());

  value2.SetUint(m_subaddress_lookahead_minor);
  json.AddMember("subaddress_lookahead_minor", value2, json.GetAllocator());

  value2.SetUint(1);
  json.AddMember("encrypted_secret_keys", value2, json.GetAllocator());

  // Serialize the JSON object
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  json.Accept(writer);
  account_data = buffer.GetString();

  // Encrypt the entire JSON object.
  std::string cipher;
  cipher.resize(account_data.size());
  keys_file_data.value().iv = crypto::rand<crypto::chacha_iv>();
  crypto::chacha20(account_data.data(), account_data.size(), key, keys_file_data.value().iv, &cipher[0]);
  keys_file_data.value().account_data = cipher;
  return keys_file_data;
}
//----------------------------------------------------------------------------------------------------
void wallet2::setup_keys(const epee::wipeable_string &password)
{
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);

  static_assert(HASH_SIZE == sizeof(crypto::chacha_key), "Mismatched sizes of hash and chacha key");
  std::array<uint8_t, HASH_SIZE+1> cache_key_data;
  memcpy(cache_key_data.data(), &key, HASH_SIZE);
  cache_key_data[HASH_SIZE] = config::HASH_KEY_WALLET_CACHE;
  auto h = crypto::sha3(cache_key_data);
  std::copy(std::begin(h.data), std::end(h.data), m_cache_key.begin());
}
//----------------------------------------------------------------------------------------------------
void wallet2::change_password(const std::string &filename, const epee::wipeable_string &original_password, const epee::wipeable_string &new_password)
{
  setup_keys(new_password);
  rewrite(filename, new_password);
  if (!filename.empty())
    store();
}
//----------------------------------------------------------------------------------------------------
/*!
 * \brief Load wallet information from wallet file.
 * \param keys_file_name Name of wallet file
 * \param password       Password of wallet file
 */
bool wallet2::load_keys(const std::string& keys_file_name, const epee::wipeable_string& password)
{
  std::string keys_file_buf;
  bool r = wallet::logic::controller::wallet::load_from_file(keys_file_name, keys_file_buf);
  THROW_WALLET_EXCEPTION_IF(!r, error::file_read_error, keys_file_name);

  // Load keys from buffer
  std::optional<crypto::chacha_key> keys_to_encrypt;
  r = wallet2::load_keys_buf(keys_file_buf, password, keys_to_encrypt);

  // Rewrite with encrypted keys if unencrypted, ignore errors
  if (r && keys_to_encrypt != std::nullopt)
  {
    bool saved_ret = store_keys(keys_file_name, password);
    if (!saved_ret)
    {
      // just moan a bit, but not fatal
      LOG_ERROR("Error saving keys file with encrypted keys, not fatal");
    }
  }
  return r;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::load_keys_buf(const std::string& keys_buf, const epee::wipeable_string& password) {
  std::optional<crypto::chacha_key> keys_to_encrypt;
  return wallet2::load_keys_buf(keys_buf, password, keys_to_encrypt);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::load_keys_buf(const std::string& keys_buf, const epee::wipeable_string& password, std::optional<crypto::chacha_key>& keys_to_encrypt) {

  // Decrypt the contents
  rapidjson::Document json;
  wallet::logic::type::wallet::keys_file_data keys_file_data;
  bool encrypted_secret_keys = false;
  bool r = ::serialization::parse_binary(keys_buf, keys_file_data);
  THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "internal error: failed to deserialize keys buffer");
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);
  std::string account_data;
  account_data.resize(keys_file_data.account_data.size());
  crypto::chacha20(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);
  json.Parse(account_data.c_str());
  if(json.IsObject())
  {
    if (!json.HasMember("key_data"))
    {
      LOG_ERROR("Field key_data not found in JSON");
      return false;
    }
    if (!json["key_data"].IsString())
    {
      LOG_ERROR("Field key_data found in JSON, but not String");
      return false;
    }
    const char *field_key_data = json["key_data"].GetString();
    account_data = std::string(field_key_data, field_key_data + json["key_data"].GetStringLength());

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, seed_language, std::string, String, false, std::string());
    if (field_seed_language_found)
    {
      set_seed_language(field_seed_language);
    }
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, always_confirm_transfers, int, Int, false, true);
    m_always_confirm_transfers = field_always_confirm_transfers;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, print_ring_members, int, Int, false, true);
    m_print_ring_members = field_print_ring_members;
    if (json.HasMember("store_tx_info"))
    {
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, store_tx_info, int, Int, true, true);
      m_store_tx_info = field_store_tx_info;
    }
    else if (json.HasMember("store_tx_keys")) // backward compatibility
    {
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, store_tx_keys, int, Int, true, true);
      m_store_tx_info = field_store_tx_keys;
    }
    else
      m_store_tx_info = true;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, default_priority, unsigned int, Uint, false, 0);
    if (field_default_priority_found)
    {
      m_default_priority = field_default_priority;
    }
    else
    {
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, default_fee_multiplier, unsigned int, Uint, false, 0);
      if (field_default_fee_multiplier_found)
        m_default_priority = field_default_fee_multiplier;
      else
        m_default_priority = 0;
    }
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, refresh_height, uint64_t, Uint64, false, 0);
    m_refresh_from_block_height = field_refresh_height;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, ask_password, AskPasswordType, Int, false, AskPasswordToDecrypt);
    m_ask_password = field_ask_password;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, default_decimal_point, int, Int, false, CRYPTONOTE_DISPLAY_DECIMAL_POINT);
    cryptonote::set_default_decimal_point(field_default_decimal_point);
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, merge_destinations, int, Int, false, false);
    m_merge_destinations = field_merge_destinations;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, confirm_export_overwrite, int, Int, false, true);
    m_confirm_export_overwrite = field_confirm_export_overwrite;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, nettype, uint8_t, Uint, false, static_cast<uint8_t>(m_nettype));
    // The network type given in the program argument is inconsistent with the network type saved in the wallet
    THROW_WALLET_EXCEPTION_IF(static_cast<uint8_t>(m_nettype) != field_nettype, error::wallet_internal_error,
    (boost::format("%s wallet cannot be opened as %s wallet")
    % (field_nettype == 0 ? "Mainnet" : "Testnet")
    % (m_nettype == MAINNET ? "mainnet" : "testnet")).str());
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, ignore_fractional_outputs, int, Int, false, true);
    m_ignore_fractional_outputs = field_ignore_fractional_outputs;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR
      (json, ignore_outputs_above, uint64_t, Uint64, false, std::numeric_limits<uint64_t>::max());
    m_ignore_outputs_above = field_ignore_outputs_above;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, ignore_outputs_below, uint64_t, Uint64, false, 0);
    m_ignore_outputs_below = field_ignore_outputs_below;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, subaddress_lookahead_major, uint32_t, Uint, false
                                        , config::lol::SUBADDRESS_LOOKAHEAD_MAJOR);
    m_subaddress_lookahead_major = field_subaddress_lookahead_major;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, subaddress_lookahead_minor, uint32_t, Uint, false
                                        , config::lol::SUBADDRESS_LOOKAHEAD_MINOR);
    m_subaddress_lookahead_minor = field_subaddress_lookahead_minor;

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, encrypted_secret_keys, uint32_t, Uint, false, false);
    encrypted_secret_keys = field_encrypted_secret_keys;
  }
  else
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, "invalid password");
    return false;
  }

  r = epee::serialization::load_t_from_binary(m_account, account_data);
  THROW_WALLET_EXCEPTION_IF(!r, error::invalid_password);

  if (r)
  {
    if (encrypted_secret_keys)
    {
      m_account.decrypt_keys(key);
    }
    else
    {
      keys_to_encrypt = key;
    }
  }
  const cryptonote::account_keys& keys = m_account.get_keys();
  r = r && crypto::verify_keys(keys.m_view_secret_key,  keys.m_account_address.m_view_public_key);
  r = r && crypto::verify_keys(keys.m_spend_secret_key, keys.m_account_address.m_spend_public_key);
  THROW_WALLET_EXCEPTION_IF(!r, error::wallet_files_doesnt_correspond, m_keys_file, m_wallet_file);

  if (r)
    setup_keys(password);

  return true;
}

/*!
 * \brief verify password for default wallet keys file.
 * \param password       Password to verify
 * \return               true if password is correct
 *
 * for verification only
 * should not mutate state, unlike load_keys()
 * can be used prior to rewriting wallet keys file, to ensure user has entered the correct password
 *
 */
bool wallet2::verify_password(const epee::wipeable_string& password)
{
  // this temporary unlocking is necessary for Windows (otherwise the file couldn't be loaded).
  bool r = wallet::logic::controller::wallet::verify_password
    (
     m_keys_file, password
     , false
     , m_kdf_rounds);
  return r;
}

void wallet2::setup_new_blockchain()
{
  cryptonote::block b;
  generate_genesis(b);
  m_blockchain.push_back(get_block_hash(b));
  add_subaddress_account("");
}

void wallet2::create_keys_file(const std::string &wallet_, const epee::wipeable_string &password)
{
  if (!wallet_.empty())
  {
    bool r = store_keys(m_keys_file, password);
    THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, m_keys_file);
  }
}

void wallet2::init_type()
{
  m_spend_view_public_keys = m_account.get_keys().m_account_address;
}

/*!
 * \brief  Generates a wallet or restores one.
 * \param  wallet_                 Name of wallet file
 * \param  password                Password of wallet file
 * \param  recovery_param          If it is a restore, the recovery key
 * \param  recover                 Whether it is a restore
 * \return                         The secret key of the generated wallet
 */
crypto::secret_key wallet2::generate
(
 const std::string& wallet_
 , const epee::wipeable_string& password
 , const std::optional<crypto::secret_key> recovery_key)
{
  clear();
  prepare_file_names(wallet_);

  if (!wallet_.empty())
  {
    std::error_code ignored_ec;
    THROW_WALLET_EXCEPTION_IF(std::filesystem::exists(m_wallet_file, ignored_ec), error::file_exists, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(std::filesystem::exists(m_keys_file,   ignored_ec), error::file_exists, m_keys_file);
  }

  crypto::secret_key retval = m_account.generate(recovery_key);

  init_type();
  setup_keys(password);

  // calculate a starting refresh height
  if(m_refresh_from_block_height == 0 && !recovery_key){
    std::string err;
    const uint64_t _target_height = get_daemon_blockchain_target_height(err);
    std::optional<uint64_t> target_height =
      err.empty()
      ? std::make_optional(_target_height)
      : std::nullopt;

    const uint64_t _local_height = get_daemon_blockchain_height(err);
    std::optional<uint64_t> local_height =
      err.empty()
      ? std::make_optional(_local_height)
      : std::nullopt;

    const uint64_t approximate_height = 0;

    m_refresh_from_block_height = wallet::logic::functional::wallet::estimate_blockchain_height
      (approximate_height, target_height, local_height);
  }

  create_keys_file(wallet_, password);

  setup_new_blockchain();

  if (!wallet_.empty())
    store();

  return retval;
}

/*!
* \brief Creates a wallet from a public address and a spend/view secret key pair.
* \param  wallet_                 Name of wallet file
* \param  password                Password of wallet file
* \param  spend_view_public_keys  The account's public address
* \param  spendkey                spend secret key
* \param  viewkey                 view secret key
*/
void wallet2::generate(const std::string& wallet_, const epee::wipeable_string& password,
  const cryptonote::spend_view_public_keys &spend_view_public_keys,
  const crypto::secret_key& spendkey, const crypto::secret_key& viewkey)
{
  clear();
  prepare_file_names(wallet_);

  if (!wallet_.empty())
  {
    std::error_code ignored_ec;
    THROW_WALLET_EXCEPTION_IF(std::filesystem::exists(m_wallet_file, ignored_ec), error::file_exists, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(std::filesystem::exists(m_keys_file,   ignored_ec), error::file_exists, m_keys_file);
  }

  m_account.create_from_keys(spend_view_public_keys, spendkey, viewkey);
  init_type();
  m_spend_view_public_keys = spend_view_public_keys;
  setup_keys(password);

  create_keys_file(wallet_, password);

  setup_new_blockchain();

  if (!wallet_.empty())
    store();
}

bool wallet2::has_unknown_output_key_images() const
{
  for (const auto &td: m_transfers)
    if (!td.m_output_key_image_known)
      return true;
  return false;
}

/*!
 * \brief Rewrites to the wallet file for wallet upgrade (doesn't generate key, assumes it's already there)
 * \param wallet_name Name of wallet file (should exist)
 * \param password    Password for wallet file
 */
void wallet2::rewrite(const std::string& wallet_name, const epee::wipeable_string& password)
{
  if (wallet_name.empty())
    return;
  prepare_file_names(wallet_name);
  std::error_code ignored_ec;
  THROW_WALLET_EXCEPTION_IF(!std::filesystem::exists(m_keys_file, ignored_ec), error::file_not_found, m_keys_file);
  bool r = store_keys(m_keys_file, password);
  THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, m_keys_file);
}
//----------------------------------------------------------------------------------------------------
void wallet2::wallet_exists(const std::string& file_path, bool& keys_file_exists, bool& wallet_file_exists)
{
  std::string keys_file, wallet_file;
  wallet::logic::controller::wallet::do_prepare_file_names(file_path, keys_file, wallet_file);

  std::error_code ignore;
  keys_file_exists = std::filesystem::exists(keys_file, ignore);
  wallet_file_exists = std::filesystem::exists(wallet_file, ignore);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::wallet_valid_path_format(const std::string& file_path)
{
  return !file_path.empty();
}
//----------------------------------------------------------------------------------------------------
bool wallet2::prepare_file_names(const std::string& file_path)
{
  wallet::logic::controller::wallet::do_prepare_file_names(file_path, m_keys_file, m_wallet_file);
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::check_connection(uint32_t *version, uint32_t timeout)
{
  THROW_WALLET_EXCEPTION_IF(!m_is_initialized, error::wallet_not_initialized);

  if (m_offline)
  {
    m_rpc_version = 0;
    if (version)
      *version = 0;
    return false;
  }

  if (!m_rpc_version)
  {
    cryptonote::COMMAND_RPC_GET_VERSION::request req_t = AUTO_VAL_INIT(req_t);
    cryptonote::COMMAND_RPC_GET_VERSION::response resp_t = AUTO_VAL_INIT(resp_t);
    bool r = m_rpc_client.invoke_http_json_rpc("get_version", req_t, resp_t);
    if(!r || resp_t.status != CORE_RPC_STATUS_OK) {
      if(version)
        *version = 0;
      return false;
    }
    m_rpc_version = resp_t.version;
  }
  if (version)
    *version = m_rpc_version;

  return true;
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_offline(bool offline)
{
  m_offline = offline;
  m_rpc_client.set_offline(offline);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::generate_chacha_key_from_secret_keys(crypto::chacha_key &key) const
{
  key = wallet::logic::functional::helper::generate_chacha_key(m_account.get_keys(), m_kdf_rounds);
  return true;
}
//----------------------------------------------------------------------------------------------------
void wallet2::generate_chacha_key_from_password(const epee::wipeable_string &pass, crypto::chacha_key &key) const
{
  crypto::generate_chacha_key(pass.data(), pass.size(), key, m_kdf_rounds);
}
//----------------------------------------------------------------------------------------------------
void wallet2::load(const std::string& wallet_, const epee::wipeable_string& password, const std::string& keys_buf, const std::string& cache_buf)
{
  clear();
  prepare_file_names(wallet_);

  // determine if loading from file system or string buffer
  bool use_fs = !wallet_.empty();
  THROW_WALLET_EXCEPTION_IF((use_fs && !keys_buf.empty()) || (!use_fs && keys_buf.empty()), error::file_read_error, "must load keys either from file system or from buffer");\

  std::error_code e;
  if (use_fs)
  {
    bool exists = std::filesystem::exists(m_keys_file, e);
    THROW_WALLET_EXCEPTION_IF(e || !exists, error::file_not_found, m_keys_file);

    // this temporary unlocking is necessary for Windows (otherwise the file couldn't be loaded).
    if (!load_keys(m_keys_file, password))
    {
      THROW_WALLET_EXCEPTION_IF(true, error::file_read_error, m_keys_file);
    }
    LOG_PRINT_L0("Loaded wallet keys file, with public address: " << m_account.get_public_address_str(m_nettype));
  }
  else if (!load_keys_buf(keys_buf, password))
  {
    THROW_WALLET_EXCEPTION_IF(true, error::file_read_error, "failed to load keys from buffer");
  }

  //keys loaded ok!
  //try to load wallet file. but even if we failed, it is not big problem
  if (use_fs && (!std::filesystem::exists(m_wallet_file, e) || e))
  {
    LOG_PRINT_L0("file not found: " << m_wallet_file << ", starting with empty blockchain");
    m_spend_view_public_keys = m_account.get_keys().m_account_address;
  }
  else if (use_fs || !cache_buf.empty())
  {
    wallet::logic::type::wallet::cache_file_data cache_file_data;
    std::string cache_file_buf;
    bool r = true;
    if (use_fs)
    {
      wallet::logic::controller::wallet::load_from_file
        (m_wallet_file, cache_file_buf, std::numeric_limits<size_t>::max());
      THROW_WALLET_EXCEPTION_IF(!r, error::file_read_error, m_wallet_file);
    }

    // try to read it as an encrypted cache
    try
    {
      LOG_PRINT_L1("Trying to decrypt cache data");

      r = ::serialization::parse_binary(use_fs ? cache_file_buf : cache_buf, cache_file_data);
      THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "internal error: failed to deserialize \"" + m_wallet_file + '\"');
      std::string cache_data;
      cache_data.resize(cache_file_data.cache_data.size());
      crypto::chacha20(cache_file_data.cache_data.data(), cache_file_data.cache_data.size(), m_cache_key, cache_file_data.iv, &cache_data[0]);

      std::stringstream iss;
      iss << cache_data;
      binary_archive<false> ar(iss);
      if (::serialization::serialize(ar, *this)) {
        ::serialization::check_stream_state(ar);
      }
    }
    catch (...)
    {
    }
    THROW_WALLET_EXCEPTION_IF(
      m_spend_view_public_keys.m_spend_public_key != m_account.get_keys().m_account_address.m_spend_public_key ||
      m_spend_view_public_keys.m_view_public_key  != m_account.get_keys().m_account_address.m_view_public_key,
      error::wallet_files_doesnt_correspond, m_keys_file, m_wallet_file);
  }

  cryptonote::block genesis;
  generate_genesis(genesis);
  crypto::hash genesis_hash = get_block_hash(genesis);

  if (m_blockchain.empty())
  {
    m_blockchain.push_back(genesis_hash);
  }
  else
  {
    check_genesis(genesis_hash);
  }

  trim_hashchain();
}
//----------------------------------------------------------------------------------------------------
void wallet2::trim_hashchain()
{
  uint64_t height = 0;

  for (const transfer_details &td: m_transfers)
    if (td.m_block_height < height)
      height = td.m_block_height;

  if (!m_blockchain.empty() && m_blockchain.size() == m_blockchain.offset())
  {
    LOG_INFO("Fixing empty hashchain");
    cryptonote::COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request req = AUTO_VAL_INIT(req);
    cryptonote::COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response res = AUTO_VAL_INIT(res);

    bool r;
    {
      req.height = m_blockchain.size() - 1;
      r = m_rpc_client.invoke_http_json_rpc("get_block_header_by_height", req, res);
    }

    if (r && res.status == CORE_RPC_STATUS_OK)
    {
      const auto maybe_hash =
        epee::string_tools::hex_to_pod<crypto::hash>
        (res.block_header.hash);

      if (!maybe_hash) {
        LOG_FATAL("invalid block header hash");
      }
      m_blockchain.refill(maybe_hash.value_or(crypto::null_hash));
    }
    else
    {
      LOG_ERROR("Failed to request block header from daemon, hash chain may be unable to sync till the wallet is loaded with a usable daemon");
    }
  }
  if (height > 0 && m_blockchain.size() > height)
  {
    --height;
    LOG_DEBUG("trimming to " << height << ", offset " << m_blockchain.offset());
    m_blockchain.trim(height);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::check_genesis(const crypto::hash& genesis_hash) const {
  std::string what("Genesis block mismatch. You probably use wallet without testnet flag with blockchain from test (or stage) network or vice versa");

  THROW_WALLET_EXCEPTION_IF(genesis_hash != m_blockchain.genesis(), error::wallet_internal_error, what);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::path() const
{
  return m_wallet_file;
}
//----------------------------------------------------------------------------------------------------
void wallet2::store()
{
  if (!m_wallet_file.empty())
    store_to("", epee::wipeable_string());
}
//----------------------------------------------------------------------------------------------------
void wallet2::store_to(const std::string &path, const epee::wipeable_string &password)
{
  trim_hashchain();

  // if file is the same, we do:
  // 1. save wallet to the *.new file
  // 2. remove old wallet file
  // 3. rename *.new to wallet_name

  // handle if we want just store wallet state to current files (ex store() replacement);
  bool same_file = true;
  if (!path.empty())
  {
    std::string canonical_path = std::filesystem::canonical(m_wallet_file).string();
    size_t pos = canonical_path.find(path);
    same_file = pos != std::string::npos;
  }


  if (!same_file)
  {
    // check if we want to store to directory which doesn't exists yet
    std::filesystem::path parent_path = std::filesystem::path(path).parent_path();

    // if path is not exists, try to create it
    if (!parent_path.empty() &&  !std::filesystem::exists(parent_path))
    {
      std::error_code ec;
      if (!std::filesystem::create_directories(parent_path, ec))
      {
        throw std::logic_error(ec.message());
      }
    }
  }

  // get wallet cache data
  std::optional<wallet::logic::type::wallet::cache_file_data> cache_file_data = get_cache_file_data(password);
  THROW_WALLET_EXCEPTION_IF(cache_file_data == std::nullopt, error::wallet_internal_error, "failed to generate wallet cache data");

  const std::string new_file = same_file ? m_wallet_file + ".new" : path;
  const std::string old_file = m_wallet_file;
  const std::string old_keys_file = m_keys_file;

  // save keys to the new file
  // if we here, main wallet file is saved and we only need to save keys and address files
  if (!same_file) {
    prepare_file_names(path);
    bool r = store_keys(m_keys_file, password);
    THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, m_keys_file);
    // remove old wallet file
    r = std::filesystem::remove(old_file);
    if (!r) {
      LOG_ERROR("error removing file: " << old_file);
    }
    // remove old keys file
    r = std::filesystem::remove(old_keys_file);
    if (!r) {
      LOG_ERROR("error removing file: " << old_keys_file);
    }
  } else {
    // save to new file
    std::ofstream ostr;
    ostr.open(new_file, std::ios_base::binary | std::ios_base::out | std::ios_base::trunc);
    binary_archive<true> oar(ostr);
    bool success = ::serialization::serialize(oar, cache_file_data.value());
    ostr.close();
    THROW_WALLET_EXCEPTION_IF(!success || !ostr.good(), error::file_save_error, new_file);

    // here we have "*.new" file, we need to rename it to be without ".new"
    std::error_code e = tools::replace_file(new_file, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(e, error::file_save_error, m_wallet_file, e);
  }
}
//----------------------------------------------------------------------------------------------------
std::optional<wallet::logic::type::wallet::cache_file_data> wallet2::get_cache_file_data(const epee::wipeable_string &passwords)
{
  trim_hashchain();
  try
  {
    std::stringstream oss;
    binary_archive<true> ar(oss);
    if (!::serialization::serialize(ar, *this))
      return std::nullopt;

    std::optional<wallet::logic::type::wallet::cache_file_data> cache_file_data = (wallet::logic::type::wallet::cache_file_data) {};
    cache_file_data.value().cache_data = oss.str();
    std::string cipher;
    cipher.resize(cache_file_data.value().cache_data.size());
    cache_file_data.value().iv = crypto::rand<crypto::chacha_iv>();
    crypto::chacha20(cache_file_data.value().cache_data.data(), cache_file_data.value().cache_data.size(), m_cache_key, cache_file_data.value().iv, &cipher[0]);
    cache_file_data.value().cache_data = cipher;
    return cache_file_data;
  }
  catch(...)
  {
    return std::nullopt;
  }
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::balance(uint32_t index_major, bool strict) const
{
  uint64_t amount = 0;
  for (const auto& i : balance_per_subaddress(index_major, strict))
    amount += i.second;
  return amount;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::unlocked_balance(uint32_t index_major, bool strict) const
{
  uint64_t amount = 0;
  for (const auto& i : unlocked_balance_per_subaddress(index_major, strict))
  {
    amount += i.second.first;
  }
  return amount;
}
//----------------------------------------------------------------------------------------------------
std::map<uint32_t, uint64_t> wallet2::balance_per_subaddress(uint32_t index_major, bool strict) const
{
  return wallet::logic::functional::wallet::balance_per_subaddress(index_major, strict, m_transfers, m_unconfirmed_txs);
}

//----------------------------------------------------------------------------------------------------
std::map<uint32_t, std::pair<uint64_t, std::pair<uint64_t, uint64_t>>>
wallet2::unlocked_balance_per_subaddress(uint32_t index_major, bool strict) const
{
  return wallet::logic::functional::wallet::unlocked_balance_per_subaddress
    (index_major, strict, m_transfers, get_blockchain_current_height());
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::balance_all(bool strict) const
{
  uint64_t r = 0;
  for (uint32_t index_major = 0; index_major < get_num_subaddress_accounts(); ++index_major)
    r += balance(index_major, strict);
  return r;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::unlocked_balance_all(bool strict)
{
  uint64_t r = 0;
  for (uint32_t index_major = 0; index_major < get_num_subaddress_accounts(); ++index_major)
  {
    r += unlocked_balance(index_major, strict);
  }
  return r;
}
//----------------------------------------------------------------------------------------------------
wallet::logic::type::wallet::transfer_container wallet2::get_transfers() const
{
  return m_transfers;
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_payments(std::list<std::pair<crypto::hash,wallet::logic::type::payment::payment_details>>& payments, uint64_t min_height, uint64_t max_height, const std::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  auto range = std::make_pair(m_payments.begin(), m_payments.end());
  std::for_each(range.first, range.second, [&payments, &min_height, &max_height, &subaddr_account, &subaddr_indices](const payment_container::value_type& x) {
    if (min_height < x.second.m_block_height && max_height >= x.second.m_block_height &&
      (!subaddr_account || *subaddr_account == x.second.m_subaddr_index.major) &&
      (subaddr_indices.empty() || subaddr_indices.count(x.second.m_subaddr_index.minor) == 1))
    {
      payments.push_back(x);
    }
  });
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_payments_out(std::list<std::pair<crypto::hash,wallet::logic::type::transfer::confirmed_transfer_details>>& confirmed_payments,
    uint64_t min_height, uint64_t max_height, const std::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  for (auto i = m_confirmed_txs.begin(); i != m_confirmed_txs.end(); ++i) {
    if (i->second.m_block_height <= min_height || i->second.m_block_height > max_height)
      continue;
    if (subaddr_account && *subaddr_account != i->second.m_subaddr_account)
      continue;
    if (!subaddr_indices.empty() && std::count_if(i->second.m_subaddr_indices.begin(), i->second.m_subaddr_indices.end(), [&subaddr_indices](uint32_t index) { return subaddr_indices.count(index) == 1; }) == 0)
      continue;
    confirmed_payments.push_back(*i);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_unconfirmed_payments_out(std::list<std::pair<crypto::hash,wallet::logic::type::transfer::unconfirmed_transfer_details>>& unconfirmed_payments, const std::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  for (auto i = m_unconfirmed_txs.begin(); i != m_unconfirmed_txs.end(); ++i) {
    if (subaddr_account && *subaddr_account != i->second.m_subaddr_account)
      continue;
    if (!subaddr_indices.empty() && std::count_if(i->second.m_subaddr_indices.begin(), i->second.m_subaddr_indices.end(), [&subaddr_indices](uint32_t index) { return subaddr_indices.count(index) == 1; }) == 0)
      continue;
    unconfirmed_payments.push_back(*i);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_unconfirmed_payments(std::list<std::pair<crypto::hash,wallet::logic::type::payment::pool_payment_details>>& unconfirmed_payments, const std::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  for (auto i = m_unconfirmed_payments.begin(); i != m_unconfirmed_payments.end(); ++i) {
    if ((!subaddr_account || *subaddr_account == i->second.m_pd.m_subaddr_index.major) &&
      (subaddr_indices.empty() || subaddr_indices.count(i->second.m_pd.m_subaddr_index.minor) == 1))
    unconfirmed_payments.push_back(*i);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::rescan_blockchain(bool hard, bool refresh)
{
  if(hard)
  {
    clear();
    setup_new_blockchain();
  }
  else
  {
    clear_soft();
  }

  if (refresh)
    this->refresh();
}

//----------------------------------------------------------------------------------------------------
// Select random input sources for transaction.
// returns:
//    direct return: amount of money found
//    modified reference: selected_transfers, a list of iterators/indices of input sources
uint64_t wallet2::select_transfers(uint64_t needed_money, std::vector<size_t> unused_transfers_indices, std::vector<size_t>& selected_transfers) const
{
  uint64_t found_money = 0;
  selected_transfers.reserve(unused_transfers_indices.size());
  while (found_money < needed_money && !unused_transfers_indices.empty())
  {
    size_t idx = wallet::logic::controller::wallet::pop_best_value_from(m_transfers, unused_transfers_indices, selected_transfers);

    const auto it = std::next(m_transfers.begin(), idx);
    selected_transfers.push_back(idx);
    found_money += it->amount();
  }

  return found_money;
}

//----------------------------------------------------------------------------------------------------
// take a pending tx and actually send it to the daemon
void wallet2::commit_tx(pending_tx& ptx)
{
  using namespace cryptonote;
  {
    // Normal submit
    COMMAND_RPC_SEND_RAW_TX::request req;
    req.tx_as_hex = epee::string_tools::buff_to_hex_nodelimer(tx_to_blob(ptx.tx));
    req.do_not_relay = false;
    req.do_sanity_checks = false;
    COMMAND_RPC_SEND_RAW_TX::response daemon_send_resp;

    {
      bool r = m_rpc_client.invoke_http_json("/send_raw_transaction", req, daemon_send_resp);
      THROW_ON_RPC_RESPONSE_ERROR(r, {}, daemon_send_resp, "sendrawtransaction", error::tx_rejected, ptx.tx, (daemon_send_resp.status), wallet::logic::functional::wallet::get_text_reason(daemon_send_resp));
    }

    // sanity checks
    for (size_t idx: ptx.selected_transfers)
    {
      THROW_WALLET_EXCEPTION_IF(idx >= m_transfers.size(), error::wallet_internal_error,
          "Bad output index in selected transfers: " + boost::lexical_cast<std::string>(idx));
    }
  }
  crypto::hash txid;

  txid = get_transaction_hash(ptx.tx);
  std::vector<cryptonote::tx_destination_entry> dests;
  uint64_t amount_in = 0;
  if (store_tx_info())
  {
    dests = ptx.dests;
    for(size_t idx: ptx.selected_transfers)
      amount_in += m_transfers[idx].amount();
  }
  const auto utd = wallet::logic::functional::wallet::get_unconfirmed_transfer_details
    (
     ptx.tx
     , amount_in
     , dests
     , ptx.change_dts.amount
     , ptx.construction_data.subaddr_account
     , ptx.construction_data.subaddr_indices
     );

  m_unconfirmed_txs[cryptonote::get_transaction_hash(ptx.tx)] = utd;

  if (store_tx_info())
  {
    m_output_secret_keys[txid] = ptx.output_secret_keys;
  }

  LOG_PRINT_L2("transaction " << txid << " generated ok and sent to daemon, output_key_images: [" << ptx.output_key_images << "]");

  for(size_t idx: ptx.selected_transfers)
  {
    set_spent(idx, 0);
  }

  //fee includes dust if dust policy specified it.
  LOG_PRINT_L1("Transaction successfully sent. <" << txid << ">" << std::endl
            << "Commission: " << print_money(ptx.fee) << " (dust sent to dust addr: " << print_money((ptx.dust_added_to_fee ? 0 : ptx.dust)) << ")" << std::endl
            << "Balance: " << print_money(balance(ptx.construction_data.subaddr_account, false)) << std::endl
            << "Unlocked: " << print_money(unlocked_balance(ptx.construction_data.subaddr_account, false)) << std::endl
            << "Please, wait for confirmation for your balance to be unlocked.");
}

void wallet2::commit_tx(std::vector<pending_tx>& ptx_vector)
{
  for (auto & ptx : ptx_vector)
  {
    commit_tx(ptx);
  }
}
//------------------------------------------------------------------------------------------------------------------------------
uint64_t wallet2::adjust_mixin(uint64_t mixin)
{
  return config::lol::mixin;
}
//----------------------------------------------------------------------------------------------------
uint32_t wallet2::adjust_priority(uint32_t priority)
{
  if (priority == 0 && m_default_priority == 0)
  {
    return 1;
  }
  return priority;
}


std::vector<size_t> wallet2::get_only_rct(const std::vector<size_t> &unused_dust_indices, const std::vector<size_t> &unused_transfers_indices) const
{
  std::vector<size_t> indices;
  for (size_t n: unused_dust_indices)
    if (m_transfers[n].is_rct())
      indices.push_back(n);
  for (size_t n: unused_transfers_indices)
    if (m_transfers[n].is_rct())
      indices.push_back(n);
  return indices;
}

std::vector<wallet::logic::type::tx::pending_tx> wallet2::create_transactions
(
 const std::vector<cryptonote::tx_destination_entry> dsts_vec
 , const size_t fake_outs_count
 , const uint64_t unlock_height
 , const uint32_t priority
 , const std::vector<uint8_t> extra
 , const uint32_t subaddr_account
 , const std::set<uint32_t> subaddr_indices_
 ) const
{
  return wallet::logic::controller::wallet::create_transactions
    (
     dsts_vec
     , fake_outs_count
     , unlock_height
     , priority
     , extra
     , subaddr_account
     , subaddr_indices_
     , m_nettype
     , m_transfers
     , m_unconfirmed_txs
     , get_blockchain_current_height()
     , m_ignore_fractional_outputs
     , m_merge_destinations
     , m_rpc_client
     , m_account.get_keys()
     , m_subaddresses
     , unlocked_balance(subaddr_account, false)
     );
}

//----------------------------------------------------------------------------------------------------
const wallet::logic::type::transfer::transfer_details &wallet2::get_transfer_details(size_t idx) const
{
  THROW_WALLET_EXCEPTION_IF(idx >= m_transfers.size(), error::wallet_internal_error, "Bad transfer index");
  return m_transfers[idx];
}
//----------------------------------------------------------------------------------------------------
std::optional<std::vector<crypto::secret_key>> wallet2::get_output_ecdh_sec_keys(const crypto::hash txid) const
{
  const auto j = m_output_secret_keys.find(txid);
  if (j != m_output_secret_keys.end()) {
    LOG_DEBUG("tx key cached for txid: " << txid);
    return j->second;
  } else {
    return {};
  }
}

std::string wallet2::get_output_ecdh_signatures(const crypto::hash &txid, const cryptonote::spend_view_public_keys &address, bool is_subaddress, const std::string &message)
{
    // fetch tx pubkey from the daemon
    COMMAND_RPC_GET_TRANSACTIONS::request req;
    COMMAND_RPC_GET_TRANSACTIONS::response res;
    req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
    req.decode_as_json = false;
    req.prune = true;

    bool ok;
    {
      ok = m_rpc_client.invoke_http_json("/get_transactions", req, res);
      THROW_WALLET_EXCEPTION_IF(!ok || (res.txs.size() != 1 && res.txs_as_hex.size() != 1),
        error::wallet_internal_error, "Failed to get transaction from daemon");
    }

    cryptonote::transaction tx;
    crypto::hash tx_hash;
    if (res.txs.size() == 1)
    {
      ok = get_full_tx(res.txs.front(), tx, tx_hash);
      THROW_WALLET_EXCEPTION_IF(!ok, error::wallet_internal_error, "Failed to parse transaction from daemon");
    }
    else
    {
      cryptonote::string_blob tx_data;
      ok = epee::string_tools::parse_hexstr_to_binbuff(res.txs_as_hex.front(), tx_data);
      THROW_WALLET_EXCEPTION_IF(!ok, error::wallet_internal_error, "Failed to parse transaction from daemon");
      const auto maybeTx = maybe_tx_from_blob(tx_data);
      THROW_WALLET_EXCEPTION_IF(!maybeTx,
          error::wallet_internal_error, "Failed to validate transaction from daemon");

      tx = *maybeTx;
      tx_hash = cryptonote::get_transaction_hash(tx);
    }

    THROW_WALLET_EXCEPTION_IF(tx_hash != txid, error::wallet_internal_error, "Failed to get the right transaction from daemon");

    // determine if the address is found in the subaddress hash table (i.e. whether the proof is outbound or inbound)
    std::vector<crypto::secret_key> output_secret_keys;
    {
      const auto maybe_output_secret_keys = get_output_ecdh_sec_keys(txid);
      THROW_WALLET_EXCEPTION_IF
        (
         !maybe_output_secret_keys
         , error::wallet_internal_error
         , "Tx secret key wasn't found in the wallet file."
         );

      output_secret_keys = *maybe_output_secret_keys;
    }

    return wallet::logic::controller::proof::get_output_ecdh_signatures(output_secret_keys, address, is_subaddress, message);
}

bool wallet2::verify_output_ecdh_signatures
(
 const crypto::hash &txid
 , const cryptonote::spend_view_public_keys &address
 , bool is_subaddress
 , const std::string &message
 , const std::string &sig_str
 , std::vector<size_t> &received_indices
 , bool &in_pool
 , uint64_t &confirmations
 )
{
  // fetch tx pubkey from the daemon
  COMMAND_RPC_GET_TRANSACTIONS::request req;
  COMMAND_RPC_GET_TRANSACTIONS::response res;
  req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
  req.decode_as_json = false;
  req.prune = true;

  bool ok;
  {
    ok = m_rpc_client.invoke_http_json("/get_transactions", req, res);
    THROW_WALLET_EXCEPTION_IF(!ok || (res.txs.size() != 1 && res.txs_as_hex.size() != 1),
      error::wallet_internal_error, "Failed to get transaction from daemon");
  }

  cryptonote::transaction tx;
  crypto::hash tx_hash;
  if (res.txs.size() == 1)
  {
    ok = get_full_tx(res.txs.front(), tx, tx_hash);
    THROW_WALLET_EXCEPTION_IF(!ok, error::wallet_internal_error, "Failed to parse transaction from daemon");
  }
  else
  {
    cryptonote::string_blob tx_data;
    ok = epee::string_tools::parse_hexstr_to_binbuff(res.txs_as_hex.front(), tx_data);
    THROW_WALLET_EXCEPTION_IF(!ok, error::wallet_internal_error, "Failed to parse transaction from daemon");

    const auto maybeTx = maybe_tx_from_blob(tx_data);
    THROW_WALLET_EXCEPTION_IF(!maybeTx, error::wallet_internal_error, "Failed to validate transaction from daemon");
    tx = *maybeTx;

    tx_hash = cryptonote::get_transaction_hash(tx);
  }

  THROW_WALLET_EXCEPTION_IF(tx_hash != txid, error::wallet_internal_error, "Failed to get the right transaction from daemon");

  const auto maybe_found = wallet::logic::pseudo_functional::proof::verify_output_ecdh_signatures
    (tx, address, is_subaddress, message, sig_str);

  if (!maybe_found) return false;

  received_indices = *maybe_found;

  in_pool = res.txs.front().in_pool;
  confirmations = 0;
  if (!in_pool)
  {
    std::string err;
    uint64_t bc_height = get_daemon_blockchain_height(err);
    if (err.empty())
      confirmations = bc_height - res.txs.front().block_height;
  }

  return true;
}

std::string wallet2::get_wallet_file() const
{
  return m_wallet_file;
}

std::string wallet2::get_keys_file() const
{
  return m_keys_file;
}

std::string wallet2::get_daemon_address() const
{
  return m_daemon_host + ":" + m_daemon_port;
}

uint64_t wallet2::get_daemon_blockchain_height(std::string &err)
{
  uint64_t height;

  std::optional<std::string> result = m_rpc_client.get_height(height);
  if (result)
  {
    err = *result;
    return 0;
  }

  err = "";
  return height;
}

uint64_t wallet2::get_daemon_blockchain_target_height(std::string &err)
{
  err = "";
  uint64_t target_height = 0;
  const auto result = m_rpc_client.get_target_height(target_height);
  if (result && *result != CORE_RPC_STATUS_OK)
  {
    err = *result;
    return 0;
  }
  return target_height;
}

// Sign a message with a private key from either the base address or a subaddress
// The signature is also bound to both keys and the signature mode (spend, view) to prevent unintended reuse
std::string wallet2::sign(const std::string &data, message_signature_type_t signature_type, cryptonote::subaddress_index index) const
{
  const cryptonote::account_keys &keys = m_account.get_keys();
  return wallet::logic::functional::signature::sign
    (data, signature_type, index, keys);
}

//----------------------------------------------------------------------------------------------------
bool wallet2::is_synced()
{
  uint64_t height;
  std::optional<std::string> result = m_rpc_client.get_height(height);
  if (result && *result != CORE_RPC_STATUS_OK)
    return false;
  return get_blockchain_current_height() >= height;
}
//----------------------------------------------------------------------------------------------------
void wallet2::generate_genesis(cryptonote::block& b) const {
  const auto bk = cryptonote::generate_genesis_block(get_config(m_nettype).GENESIS_TX, get_config(m_nettype).GENESIS_NONCE);

  if (!bk) {
    LOG_ERROR_AND_THROW("failed to generate genesis block");
  }

  b = *bk;
}


} // tools
