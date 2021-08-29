// Copyright (c) 2017-2020, The Monero Project
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

#pragma once

#include "device.hpp"

namespace hw {

    namespace core {

        void register_all(std::map<std::string, std::unique_ptr<device>> &registry);

        class device_default : public hw::device {
        public:
            device_default();
            ~device_default();

            device_default(const device_default &device) = delete;
            device_default& operator=(const device_default &device) = delete;

            explicit operator bool() const override { return false; };

             /* ======================================================================= */
            /*                              SETUP/TEARDOWN                             */
            /* ======================================================================= */
            bool set_name(const std::string &name) override;
            const std::string get_name() const override;

            bool init(void) override;
            bool release() override;

            bool connect(void) override;
            bool disconnect() override;

            bool set_mode(device_mode mode) override;

            device_type get_type() const override {return device_type::SOFTWARE;};

            /* ======================================================================= */
            /*  LOCKER                                                                 */
            /* ======================================================================= */
            void lock(void)  override;
            void unlock(void) override;
            bool try_lock(void) override;

            /* ======================================================================= */
            /*                             WALLET & ADDRESS                            */
            /* ======================================================================= */
            bool  get_public_address(cryptonote::account_public_address &pubkey) override;
            bool  get_secret_keys(crypto::secret_key &viewkey , crypto::secret_key &spendkey) override;
            bool  generate_chacha_key(const cryptonote::account_keys &keys, crypto::chacha_key &key, uint64_t kdf_rounds) override;

            /* ======================================================================= */
            /*                               SUB ADDRESS                               */
            /* ======================================================================= */
            crypto::public_key  get_subaddress_spend_public_key(const cryptonote::account_keys& keys, const cryptonote::subaddress_index& index) override;
            std::vector<crypto::public_key>  get_subaddress_spend_public_keys(const cryptonote::account_keys &keys, uint32_t account, uint32_t begin, uint32_t end) override;
            cryptonote::account_public_address  get_subaddress(const cryptonote::account_keys& keys, const cryptonote::subaddress_index &index) override;
            crypto::secret_key  get_subaddress_secret_key(const crypto::secret_key &sec, const cryptonote::subaddress_index &index) override;

            /* ======================================================================= */
            /*                            DERIVATION & KEY                             */
            /* ======================================================================= */
            bool  verify_keys(const crypto::secret_key &secret_key, const crypto::public_key &public_key)  override;


            /* ======================================================================= */
            /*                               TRANSACTION                               */
            /* ======================================================================= */

            bool  open_tx(crypto::secret_key &tx_key) override;
            void get_transaction_prefix_hash(const cryptonote::transaction_prefix& tx, crypto::hash& h) override;

            bool generate_output_ephemeral_keys
            (
            const size_t tx_version
            , const cryptonote::account_keys &sender_account_keys
            , const crypto::public_key &txkey_pub
            ,  const crypto::secret_key &tx_key
            , const cryptonote::tx_destination_entry &dst_entr
            , const std::optional<cryptonote::account_public_address> &change_addr
            , const size_t output_index
            , const bool &need_additional_txkeys
            , const std::vector<crypto::secret_key> &additional_tx_keys
            , std::vector<crypto::public_key> &additional_tx_public_keys
            , rct::rct_scalarV &amount_keys
            , crypto::public_key &out_eph_public_key
            ) override;

            bool clsag_prepare
            (
             const rct::rct_scalar &p
             , const rct::rct_scalar &z
             , rct::rct_point &I
             , rct::rct_point &D
             , const rct::rct_point &H
             , rct::rct_scalar &a
             , rct::rct_point &aG
             , rct::rct_point &aH
             ) override;

            rct::rct_scalar clsag_hash(const crypto::dataS data) override;
            bool clsag_sign
            (
             const rct::rct_scalar &c
             , const rct::rct_scalar &a
             , const rct::rct_scalar &p
             , const rct::rct_scalar &z
             , const rct::rct_scalar &mu_P
             , const rct::rct_scalar &mu_C
             , rct::rct_scalar &s
             ) override;

            bool  close_tx(void) override;
        };

    }



}

