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

#pragma once

#include "wallet/api/rpc_client.h"
#include "wallet/api/wallet_errors.h"

#include "wallet/logic/type/typedef.hpp"
#include "wallet/logic/type/hashchain.hpp"
#include "wallet/logic/type/payment.hpp"
#include "wallet/logic/type/transfer.hpp"
#include "wallet/logic/type/tx.hpp"
#include "wallet/logic/type/wallet.hpp"
#include "wallet/logic/type/message_signature.hpp"

#include "network/type/http.h"

// remove the following 3, the wallet might become unusable (won't start)
#include "tools/serialization/string.h"
#include "tools/serialization/pair.h"
#include "tools/serialization/containers.h"

#include "tools/common/password.h"
#include "tools/common/notify.h"

#include "tools/epee/include/net/http_abstract_invoke.h"

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.wallet2"

namespace tools
{
  using namespace wallet::logic::type::wallet;
  using namespace wallet::logic::type::payment;
  using namespace wallet::logic::type::transfer;
  using namespace wallet::logic::type::tx;

  class i_wallet2_callback
  {
  public:
    // Full wallet callbacks
    virtual void on_new_block(uint64_t height, const cryptonote::block& block) {}
    virtual void on_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount, const cryptonote::subaddress_index& subaddr_index, bool is_change, uint64_t unlock_time) {}
    virtual void on_unconfirmed_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount, const cryptonote::subaddress_index& subaddr_index) {}
    virtual void on_money_spent(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& in_tx, uint64_t amount, const cryptonote::transaction& spend_tx, const cryptonote::subaddress_index& subaddr_index) {}
    virtual void on_skip_transaction(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx) {}
    virtual std::optional<epee::wipeable_string> on_get_password(const char *reason) { return std::nullopt; }
    // Common callbacks
    virtual void on_pool_tx_removed(const crypto::hash &txid) {}
    virtual ~i_wallet2_callback() {}
  };

  class wallet2
  {
  public:
    static constexpr const std::chrono::seconds rpc_timeout = std::chrono::minutes(3) + std::chrono::seconds(30);

    enum AskPasswordType {
      AskPasswordNever = 0,
      AskPasswordOnAction = 1,
      AskPasswordToDecrypt = 2,
    };

    static const char* tr(const char* str);

    static bool has_testnet_option(const boost::program_options::variables_map& vm);
    static std::string device_name_option(const boost::program_options::variables_map& vm);
    static void init_options(boost::program_options::options_description& desc_params);

    //! Uses stdin and stdout. Returns a wallet2 and password for `wallet_file` if no errors.
    static std::pair<std::unique_ptr<wallet2>, password_container>
      make_from_file(const boost::program_options::variables_map& vm, bool unattended, const std::string& wallet_file, const std::function<std::optional<password_container>(const char *, bool)> &password_prompter);

    //! Uses stdin and stdout. Returns a wallet2 and password for wallet with no file if no errors.
    static std::pair<std::unique_ptr<wallet2>, password_container> make_new(const boost::program_options::variables_map& vm, bool unattended, const std::function<std::optional<password_container>(const char *, bool)> &password_prompter);

    wallet2
    (
     cryptonote::network_type nettype = cryptonote::MAINNET
     , uint64_t kdf_rounds = 1
     , bool unattended = false
     , std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory
     = std::make_unique<net::http::client_factory>()
     );
    ~wallet2();

    typedef serializable_unordered_multimap<crypto::hash, payment_details> payment_container;

    /*!
     * \brief Generates a wallet or restores one.
     * \param  wallet_              Name of wallet file
     * \param  password             Password of wallet file
     * \param  recovery_param       If it is a restore, the recovery key
     * \param  recover              Whether it is a restore
     * \return                      The secret key of the generated wallet
     */
    crypto::secret_key generate(const std::string& wallet, const epee::wipeable_string& password,
      const crypto::secret_key& recovery_param = crypto::secret_key(), bool recover = false);
    /*!
     * \brief Creates a wallet from a public address and a spend/view secret key pair.
     * \param  wallet_                 Name of wallet file
     * \param  password                Password of wallet file
     * \param  account_public_address  The account's public address
     * \param  spendkey                spend secret key
     * \param  viewkey                 view secret key
     */
    void generate(const std::string& wallet, const epee::wipeable_string& password,
      const cryptonote::account_public_address &account_public_address,
      const crypto::secret_key& spendkey, const crypto::secret_key& viewkey);
    /*!
     * \brief Rewrites to the wallet file for wallet upgrade (doesn't generate key, assumes it's already there)
     * \param wallet_name Name of wallet file (should exist)
     * \param password    Password for wallet file
     */
    void rewrite(const std::string& wallet_name, const epee::wipeable_string& password);
    void load(const std::string& wallet, const epee::wipeable_string& password, const std::string& keys_buf = "", const std::string& cache_buf = "");
    void store();
    /*!
     * \brief store_to  Stores wallet to another file(s), deleting old ones
     * \param path      Path to the wallet file (keys and address filenames will be generated based on this filename)
     * \param password  Password to protect new wallet (TODO: probably better save the password in the wallet object?)
     */
    void store_to(const std::string &path, const epee::wipeable_string &password);
    /*!
     * \brief get_keys_file_data  Get wallet keys data which can be stored to a wallet file.
     * \param password            Password of the encrypted wallet buffer (TODO: probably better save the password in the wallet object?)
     * \return                    Encrypted wallet keys data which can be stored to a wallet file
     */
    std::optional<wallet::logic::type::wallet::keys_file_data> get_keys_file_data(const epee::wipeable_string& password);
    /*!
     * \brief get_cache_file_data   Get wallet cache data which can be stored to a wallet file.
     * \param password              Password to protect the wallet cache data (TODO: probably better save the password in the wallet object?)
     * \return                      Encrypted wallet cache data which can be stored to a wallet file
     */
    std::optional<wallet::logic::type::wallet::cache_file_data> get_cache_file_data(const epee::wipeable_string& password);

    std::string path() const;

    /*!
     * \brief verifies given password is correct for default wallet keys file
     */
    bool verify_password(const epee::wipeable_string& password);
    cryptonote::account_base& get_account(){return m_account;}
    const cryptonote::account_base& get_account()const{return m_account;}

    void set_refresh_from_block_height(uint64_t height) {m_refresh_from_block_height = height;}
    uint64_t get_refresh_from_block_height() const {return m_refresh_from_block_height;}

    void set_explicit_refresh_from_block_height(bool expl) {m_explicit_refresh_from_block_height = expl;}
    bool get_explicit_refresh_from_block_height() const {return m_explicit_refresh_from_block_height;}

    bool deinit();
    bool init(std::string daemon_address = "http://localhost:8080",
              uint64_t upper_transaction_weight_limit = 0);
    bool set_daemon(std::string daemon_address = "http://localhost:8080");
    void stop() { m_run.store(false, std::memory_order_relaxed); }

    i_wallet2_callback* callback() const { return m_callback; }
    void callback(i_wallet2_callback* callback) { m_callback = callback; }

    bool get_seed(epee::wipeable_string& electrum_words, const epee::wipeable_string &passphrase = epee::wipeable_string());

    /*!
    * \brief Checks if light wallet. A light wallet sends view key to a server where the blockchain is scanned.
    */

    /*!
     * \brief Gets the seed language
     */
    const std::string &get_seed_language() const;
    /*!
     * \brief Sets the seed language
     */
    void set_seed_language(const std::string &language);

    // Subaddress scheme
    cryptonote::account_public_address get_subaddress(const cryptonote::subaddress_index& index) const;
    cryptonote::account_public_address get_address() const { return get_subaddress({0,0}); }
    std::optional<cryptonote::subaddress_index> get_subaddress_index(const cryptonote::account_public_address& address) const;
    crypto::public_key get_subaddress_spend_public_key(const cryptonote::subaddress_index& index) const;
    std::vector<crypto::public_key> get_subaddress_spend_public_keys(uint32_t account, uint32_t begin, uint32_t end) const;
    std::string get_subaddress_as_str(const cryptonote::subaddress_index& index) const;
    std::string get_address_as_str() const { return get_subaddress_as_str({0, 0}); }
    void add_subaddress_account(const std::string& label);
    size_t get_num_subaddress_accounts() const { return m_subaddress_labels.size(); }
    size_t get_num_subaddresses(uint32_t index_major) const { return index_major < m_subaddress_labels.size() ? m_subaddress_labels[index_major].size() : 0; }
    void add_subaddress(uint32_t index_major, const std::string& label); // throws when index is out of bound
    void expand_subaddresses(const cryptonote::subaddress_index& index);
    void create_one_off_subaddress(const cryptonote::subaddress_index& index);
    std::string get_subaddress_label(const cryptonote::subaddress_index& index) const;
    void set_subaddress_label(const cryptonote::subaddress_index &index, const std::string &label);
    void set_subaddress_lookahead(size_t major, size_t minor);
    std::pair<size_t, size_t> get_subaddress_lookahead() const { return {m_subaddress_lookahead_major, m_subaddress_lookahead_minor}; }
    void refresh();
    void refresh(uint64_t start_height, uint64_t & blocks_fetched);
    void refresh(uint64_t start_height, uint64_t & blocks_fetched, bool& received_money, bool check_pool = true);
    bool refresh(uint64_t & blocks_fetched, bool& received_money, bool& ok);

    cryptonote::network_type nettype() const { return m_nettype; }
    bool has_unknown_key_images() const;
    bool key_on_device() const { return get_device_type() != hw::device::device_type::SOFTWARE; }
    hw::device::device_type get_device_type() const { return m_key_device_type; }
    bool reconnect_device();

    // locked & unlocked balance of given or current subaddress account
    uint64_t balance(uint32_t subaddr_index_major, bool strict) const;
    uint64_t unlocked_balance(uint32_t subaddr_index_major, bool strict, uint64_t *blocks_to_unlock = NULL, uint64_t *time_to_unlock = NULL);
    // locked & unlocked balance per subaddress of given or current subaddress account
    std::map<uint32_t, uint64_t> balance_per_subaddress(uint32_t subaddr_index_major, bool strict) const;
    std::map<uint32_t, std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> unlocked_balance_per_subaddress(uint32_t subaddr_index_major, bool strict);
    // all locked & unlocked balances of all subaddress accounts
    uint64_t balance_all(bool strict) const;
    uint64_t unlocked_balance_all(bool strict, uint64_t *blocks_to_unlock = NULL, uint64_t *time_to_unlock = NULL);
    void transfer_selected_rct(std::vector<cryptonote::tx_destination_entry> dsts, const std::vector<size_t>& selected_transfers, size_t fake_outputs_count,
      std::vector<std::vector<wallet::logic::type::get_outs_entry>> &outs,
      uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, cryptonote::transaction& tx, pending_tx &ptx);

    void commit_tx(pending_tx& ptx_vector);
    void commit_tx(std::vector<pending_tx>& ptx_vector);
    // load unsigned_tx_set from file.
    std::vector<wallet::logic::type::tx::pending_tx> create_transactions_2
    (
     const std::vector<cryptonote::tx_destination_entry> dsts_vec
     , const size_t fake_outs_count
     , const uint64_t unlock_time
     , const uint32_t priority
     , const std::vector<uint8_t> extra
     , const uint32_t subaddr_account
     , const std::set<uint32_t> subaddr_indices_
     );

    bool sanity_check(const std::vector<wallet::logic::type::tx::pending_tx> &ptx_vector, std::vector<cryptonote::tx_destination_entry> dsts) const;
    void device_show_address(uint32_t account_index, uint32_t address_index);
    bool check_connection(uint32_t *version = NULL, uint32_t timeout = 200000);
    void get_transfers(wallet::logic::type::wallet::transfer_container& incoming) const;
    void get_payments(std::list<std::pair<crypto::hash,wallet::logic::type::payment::payment_details>>& payments, uint64_t min_height, uint64_t max_height = (uint64_t)-1, const std::optional<uint32_t>& subaddr_account = std::nullopt, const std::set<uint32_t>& subaddr_indices = {}) const;
    void get_payments_out(std::list<std::pair<crypto::hash,wallet::logic::type::transfer::confirmed_transfer_details>>& confirmed_payments,
      uint64_t min_height, uint64_t max_height = (uint64_t)-1, const std::optional<uint32_t>& subaddr_account = std::nullopt, const std::set<uint32_t>& subaddr_indices = {}) const;
    void get_unconfirmed_payments_out(std::list<std::pair<crypto::hash,wallet::logic::type::transfer::unconfirmed_transfer_details>>& unconfirmed_payments, const std::optional<uint32_t>& subaddr_account = std::nullopt, const std::set<uint32_t>& subaddr_indices = {}) const;
    void get_unconfirmed_payments(std::list<std::pair<crypto::hash,wallet::logic::type::payment::pool_payment_details>>& unconfirmed_payments, const std::optional<uint32_t>& subaddr_account = std::nullopt, const std::set<uint32_t>& subaddr_indices = {}) const;

    uint64_t get_blockchain_current_height() const { return m_blockchain.size(); }
    void rescan_spent();
    void rescan_blockchain(bool hard, bool refresh = true);
    bool is_transfer_unlocked(const transfer_details& td);
    bool is_transfer_unlocked(const uint64_t unlock_time, const uint64_t block_height);

    BEGIN_SERIALIZE_OBJECT()
      MAGIC_FIELD("monero wallet cache")
      VERSION_FIELD(0)
      FIELD(m_blockchain)
      FIELD(m_transfers)
      FIELD(m_account_public_address)
      FIELD(m_key_images)
      FIELD(m_unconfirmed_txs)
      FIELD(m_payments)
      FIELD(m_tx_keys)
      FIELD(m_confirmed_txs)
      FIELD(m_unconfirmed_payments)
      FIELD(m_pub_keys)
      FIELD(m_scanned_pool_txs[0])
      FIELD(m_scanned_pool_txs[1])
      FIELD(m_subaddresses)
      FIELD(m_subaddress_labels)
      FIELD(m_additional_tx_keys)
      FIELD(m_attributes)
      FIELD(m_account_tags)
      FIELD(m_device_last_key_image_sync)
      FIELD(m_cold_key_images)
    END_SERIALIZE()

    /*!
     * \brief  Check if wallet keys and bin files exist
     * \param  file_path           Wallet file path
     * \param  keys_file_exists    Whether keys file exists
     * \param  wallet_file_exists  Whether bin file exists
     */
    static void wallet_exists(const std::string& file_path, bool& keys_file_exists, bool& wallet_file_exists);
    /*!
     * \brief  Check if wallet file path is valid format
     * \param  file_path      Wallet file path
     * \return                Whether path is valid format
     */
    static bool wallet_valid_path_format(const std::string& file_path);

    bool always_confirm_transfers() const { return m_always_confirm_transfers; }
    void always_confirm_transfers(bool always) { m_always_confirm_transfers = always; }
    bool print_ring_members() const { return m_print_ring_members; }
    void print_ring_members(bool value) { m_print_ring_members = value; }
    bool store_tx_info() const { return m_store_tx_info; }
    void store_tx_info(bool store) { m_store_tx_info = store; }
    uint32_t get_default_priority() const { return m_default_priority; }
    void set_default_priority(uint32_t p) { m_default_priority = p; }
    void merge_destinations(bool merge) { m_merge_destinations = merge; }
    bool merge_destinations() const { return m_merge_destinations; }
    bool confirm_export_overwrite() const { return m_confirm_export_overwrite; }
    void confirm_export_overwrite(bool always) { m_confirm_export_overwrite = always; }
    bool ignore_fractional_outputs() const { return m_ignore_fractional_outputs; }
    void ignore_fractional_outputs(bool value) { m_ignore_fractional_outputs = value; }
    const std::string & device_name() const { return m_device_name; }
    void device_name(const std::string & device_name) { m_device_name = device_name; }

    bool get_tx_key_cached(const crypto::hash &txid, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys) const;
    bool get_tx_key(const crypto::hash &txid, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys);
    void check_tx_key(const crypto::hash &txid, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys, const cryptonote::account_public_address &address, uint64_t &received, bool &in_pool, uint64_t &confirmations);
    void check_tx_key_helper(const crypto::hash &txid, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, const cryptonote::account_public_address &address, uint64_t &received, bool &in_pool, uint64_t &confirmations);
    std::string get_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address, bool is_subaddress, const std::string &message);
    bool check_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address, bool is_subaddress, const std::string &message, const std::string &sig_str, uint64_t &received, bool &in_pool, uint64_t &confirmations);

    size_t get_num_transfer_details() const { return m_transfers.size(); }
    const transfer_details &get_transfer_details(size_t idx) const;

    std::string get_wallet_file() const;
    std::string get_keys_file() const;
    std::string get_daemon_address() const;
    uint64_t get_daemon_blockchain_height(std::string& err);
    uint64_t get_daemon_blockchain_target_height(std::string& err);

    size_t pop_best_value(std::vector<size_t> &unused_dust_indices, const std::vector<size_t>& selected_transfers, bool smallest = false) const;

    std::string sign(const std::string &data,
                     wallet::logic::type::message_signature::message_signature_type_t signature_type,
                     cryptonote::subaddress_index index) const;

    void update_pool_state(std::vector<std::tuple<cryptonote::transaction, crypto::hash, bool>> &process_txs, bool refreshed = false);
    void process_pool_state(const std::vector<std::tuple<cryptonote::transaction, crypto::hash, bool>> &txs);
    void remove_obsolete_pool_txs(const std::vector<crypto::hash> &tx_hashes);

    bool is_synced();

    uint64_t adjust_mixin(uint64_t mixin);

    uint32_t adjust_priority(uint32_t priority);

    template<class t_request, class t_response>
    bool invoke_http_json(const std::string_view uri, const t_request& req, t_response& res, std::chrono::milliseconds timeout = std::chrono::seconds(15), const std::string_view http_method = "POST")
    {
      if (m_offline) return false;
      std::lock_guard<std::recursive_mutex> lock(m_daemon_rpc_mutex);
      return epee::net_utils::invoke_http_json(uri, req, res, *m_http_client, timeout, http_method);
    }

    template<class t_request, class t_response>
    bool invoke_http_bin(const std::string_view uri, const t_request& req, t_response& res, std::chrono::milliseconds timeout = std::chrono::seconds(15), const std::string_view http_method = "POST")
    {
      if (m_offline) return false;
      std::lock_guard<std::recursive_mutex> lock(m_daemon_rpc_mutex);
      return epee::net_utils::invoke_http_bin(uri, req, res, *m_http_client, timeout, http_method);
    }

    template<class t_request, class t_response>
    bool invoke_http_json_rpc(const std::string_view uri, const std::string& method_name, const t_request& req, t_response& res, std::chrono::milliseconds timeout = std::chrono::seconds(15), const std::string_view http_method = "POST", const std::string& req_id = "0")
    {
      if (m_offline) return false;
      std::lock_guard<std::recursive_mutex> lock(m_daemon_rpc_mutex);
      return epee::net_utils::invoke_http_json_rpc(uri, method_name, req, res, *m_http_client, timeout, http_method, req_id);
    }

    void change_password(const std::string &filename, const epee::wipeable_string &original_password, const epee::wipeable_string &new_password);

    void set_tx_notify(const std::shared_ptr<tools::Notify> &notify) { m_tx_notify = notify; }

    bool is_tx_spendtime_unlocked(const uint64_t unlock_time);
    void set_offline(bool offline = true);

    static std::string get_default_daemon_address() {
      std::unique_lock<std::mutex> lock(default_daemon_address_lock);
      return default_daemon_address;
    };

  private:
    /*!
     * \brief  Stores wallet information to wallet file.
     * \param  keys_file_name Name of wallet file
     * \param  password       Password of wallet file
     * \return                Whether it was successful.
     */
    bool store_keys(const std::string& keys_file_name, const epee::wipeable_string& password);
    /*!
     * \brief Load wallet keys information from wallet file.
     * \param keys_file_name Name of wallet file
     * \param password       Password of wallet file
     */
    bool load_keys(const std::string& keys_file_name, const epee::wipeable_string& password);
    /*!
     * \brief Load wallet keys information from a string buffer.
     * \param keys_buf       Keys buffer to load
     * \param password       Password of keys buffer
     */
    bool load_keys_buf(const std::string& keys_buf, const epee::wipeable_string& password);
    bool load_keys_buf(const std::string& keys_buf, const epee::wipeable_string& password, std::optional<crypto::chacha_key>& keys_to_encrypt);
    void process_new_transaction(const crypto::hash &txid, const cryptonote::transaction& tx, const std::vector<uint64_t> &o_indices, uint64_t height, uint8_t block_version, uint64_t ts, bool miner_tx, bool pool, bool double_spend_seen, const tx_cache_data &tx_cache_data);
    bool should_skip_block(const cryptonote::block &b, uint64_t height) const;
    void process_new_blockchain_entry(const cryptonote::block& b, const cryptonote::block_complete_entry& bche, const parsed_block &parsed_block, const crypto::hash& bl_id, uint64_t height, const std::vector<tx_cache_data> &tx_cache_data, size_t tx_cache_data_offset);
    void detach_blockchain(uint64_t height);
    void get_short_chain_history(std::list<crypto::hash>& ids, uint64_t granularity = 1) const;
    bool clear();
    void clear_soft();
    void pull_blocks(uint64_t start_height, uint64_t& blocks_start_height, const std::list<crypto::hash> &short_chain_history, std::vector<cryptonote::block_complete_entry> &blocks, std::vector<cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::block_output_indices> &o_indices, uint64_t &current_height);
    void pull_hashes(uint64_t start_height, uint64_t& blocks_start_height, const std::list<crypto::hash> &short_chain_history, std::vector<crypto::hash> &hashes);
    void fast_refresh(uint64_t stop_height, uint64_t &blocks_start_height, std::list<crypto::hash> &short_chain_history, bool force = false);
    void pull_and_parse_next_blocks(uint64_t start_height, uint64_t &blocks_start_height, std::list<crypto::hash> &short_chain_history, const std::vector<cryptonote::block_complete_entry> &prev_blocks, const std::vector<parsed_block> &prev_parsed_blocks, std::vector<cryptonote::block_complete_entry> &blocks, std::vector<parsed_block> &parsed_blocks, bool &last, bool &error, std::exception_ptr &exception);
    void process_parsed_blocks(uint64_t start_height, const std::vector<cryptonote::block_complete_entry> &blocks, const std::vector<parsed_block> &parsed_blocks, uint64_t& blocks_added);
    uint64_t select_transfers(uint64_t needed_money, std::vector<size_t> unused_transfers_indices, std::vector<size_t>& selected_transfers) const;
    bool prepare_file_names(const std::string& file_path);
    void process_unconfirmed(const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t height);
    void process_outgoing(const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t height, uint64_t ts, uint64_t spent, uint64_t received, uint32_t subaddr_account, const std::set<uint32_t>& subaddr_indices);
    void add_unconfirmed_tx(const cryptonote::transaction& tx, uint64_t amount_in, const std::vector<cryptonote::tx_destination_entry> &dests, uint64_t change_amount, uint32_t subaddr_account, const std::set<uint32_t>& subaddr_indices);
    void generate_genesis(cryptonote::block& b) const;
    void check_genesis(const crypto::hash& genesis_hash) const; //throws
    bool generate_chacha_key_from_secret_keys(crypto::chacha_key &key) const;
    void generate_chacha_key_from_password(const epee::wipeable_string &pass, crypto::chacha_key &key) const;
    void check_acc_out_precomp(const cryptonote::tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, tx_scan_info_t &tx_scan_info) const;
    void check_acc_out_precomp(const cryptonote::tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, const is_out_data *is_out_data, tx_scan_info_t &tx_scan_info) const;
    void check_acc_out_precomp_once(const cryptonote::tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, const is_out_data *is_out_data, tx_scan_info_t &tx_scan_info, bool &already_seen) const;
    void parse_block_round(const cryptonote::blobdata &blob, cryptonote::block &bl, crypto::hash &bl_id, bool &error) const;
    uint64_t get_upper_transaction_weight_limit();
    std::vector<uint64_t> get_unspent_amounts_vector(bool strict);
    std::vector<size_t> pick_preferred_rct_inputs(uint64_t needed_money, uint32_t subaddr_account, const std::set<uint32_t> &subaddr_indices);
    void set_spent(size_t idx, uint64_t height);
    void set_unspent(size_t idx);
    bool is_spent(const transfer_details &td, bool strict = true) const;
    bool is_spent(size_t idx, bool strict = true) const;
    void get_outs(std::vector<std::vector<wallet::logic::type::get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count, bool rct) const;
    void get_outs(std::vector<std::vector<wallet::logic::type::get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count, std::vector<uint64_t> &rct_offsets) const;
    bool tx_add_fake_output(std::vector<std::vector<wallet::logic::type::get_outs_entry>> &outs, uint64_t global_index, const crypto::public_key& tx_public_key, const rct::key& mask, uint64_t real_index, bool unlocked) const;
    std::vector<size_t> get_only_rct(const std::vector<size_t> &unused_dust_indices, const std::vector<size_t> &unused_transfers_indices) const;
    void scan_output(const cryptonote::transaction &tx, bool miner_tx, const crypto::public_key &tx_pub_key, size_t i, tx_scan_info_t &tx_scan_info, int &num_vouts_received, std::unordered_map<cryptonote::subaddress_index, uint64_t> &tx_money_got_in_outs, std::vector<size_t> &outs, bool pool);
    void trim_hashchain();
    void setup_keys(const epee::wipeable_string &password);
    size_t get_transfer_details(const crypto::key_image &ki) const;

    void cache_tx_data(const cryptonote::transaction& tx, const crypto::hash &txid, tx_cache_data &tx_cache_data) const;

    void init_type(hw::device::device_type device_type);
    void setup_new_blockchain();
    void create_keys_file(const std::string &wallet_, const epee::wipeable_string &password);

    bool should_expand(const cryptonote::subaddress_index &index) const;
    bool spends_one_of_ours(const cryptonote::transaction &tx) const;

    cryptonote::account_base m_account;
    std::string m_daemon_address;
    std::string m_wallet_file;
    std::string m_keys_file;
    const std::unique_ptr<epee::net_utils::http::abstract_http_client> m_http_client;
    wallet::logic::type::hashchain m_blockchain;
    serializable_unordered_map<crypto::hash, unconfirmed_transfer_details> m_unconfirmed_txs;
    serializable_unordered_map<crypto::hash, confirmed_transfer_details> m_confirmed_txs;
    serializable_unordered_multimap<crypto::hash, pool_payment_details> m_unconfirmed_payments;
    serializable_unordered_map<crypto::hash, crypto::secret_key> m_tx_keys;
    serializable_unordered_map<crypto::hash, std::vector<crypto::secret_key>> m_additional_tx_keys;

    wallet::logic::type::wallet::transfer_container m_transfers;
    payment_container m_payments;
    serializable_unordered_map<crypto::key_image, size_t> m_key_images;
    serializable_unordered_map<crypto::public_key, size_t> m_pub_keys;
    cryptonote::account_public_address m_account_public_address;
    serializable_unordered_map<crypto::public_key, cryptonote::subaddress_index> m_subaddresses;
    std::vector<std::vector<std::string>> m_subaddress_labels;
    serializable_unordered_map<std::string, std::string> m_attributes;
    std::pair<serializable_map<std::string, std::string>, std::vector<std::string>> m_account_tags;
    uint64_t m_upper_transaction_weight_limit; //TODO: auto-calc this value or request from daemon, now use some fixed value
    serializable_unordered_map<crypto::public_key, crypto::key_image> m_cold_key_images;

    std::atomic<bool> m_run;

    std::recursive_mutex m_daemon_rpc_mutex;

    i_wallet2_callback* m_callback;
    hw::device::device_type m_key_device_type;
    cryptonote::network_type m_nettype;
    uint64_t m_kdf_rounds;
    std::string seed_language; /*!< Language of the mnemonics (seed). */
    bool m_always_confirm_transfers;
    bool m_print_ring_members;
    bool m_store_tx_info; /*!< request txkey to be returned in RPC, and store in the wallet cache file */
    uint32_t m_default_priority;
    uint64_t m_refresh_from_block_height;
    // If m_refresh_from_block_height is explicitly set to zero we need this to differentiate it from the case that
    // m_refresh_from_block_height was defaulted to zero.*/
    bool m_explicit_refresh_from_block_height;
    AskPasswordType m_ask_password;
    bool m_merge_destinations;
    bool m_confirm_export_overwrite;
    bool m_ignore_fractional_outputs;
    uint64_t m_ignore_outputs_above;
    uint64_t m_ignore_outputs_below;
    bool m_is_initialized;
    RPC_Client m_rpc_client;
    std::unordered_set<crypto::hash> m_scanned_pool_txs[2];
    size_t m_subaddress_lookahead_major, m_subaddress_lookahead_minor;
    std::string m_device_name;
    uint64_t m_device_last_key_image_sync;
    bool m_offline;
    uint32_t m_rpc_version;

    crypto::chacha_key m_cache_key;

    std::shared_ptr<tools::Notify> m_tx_notify;

    static std::mutex default_daemon_address_lock;
    static std::string default_daemon_address;
  };
}
