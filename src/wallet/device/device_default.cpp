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




#include "device_default.hpp"


#include "cryptonote/tx/cryptonote_tx_utils.h"

#include "tools/epee/include/int-util.h"
#include "tools/epee/include/string_tools.h"

#include "math/ringct/controller/rctGen.hpp"


namespace hw {

    namespace core {

        device_default::device_default() { }

        device_default::~device_default() { }

        /* ======================================================================= */
        /*                              SETUP/TEARDOWN                             */
        /* ======================================================================= */
        bool device_default::set_name(const std::string &name)  {
            this->name = name;
            return true;
        }
        const std::string device_default::get_name()  const {
            return this->name;
        }

        bool device_default::init(void) {
            return true;
        }
        bool device_default::release() {
            return true;
        }

        bool device_default::connect(void) {
            return true;
        }
        bool device_default::disconnect() {
            return true;
        }

        bool  device_default::set_mode(device_mode mode) {
            return device::set_mode(mode);
        }

        /* ======================================================================= */
        /*  LOCKER                                                                 */
        /* ======================================================================= */

        void device_default::lock() { }

        bool device_default::try_lock() { return true; }

        void device_default::unlock() { }

        /* ======================================================================= */
        /*                             WALLET & ADDRESS                            */
        /* ======================================================================= */

        bool  device_default::generate_chacha_key(const cryptonote::account_keys &keys, crypto::chacha_key &key, uint64_t kdf_rounds) {
            const crypto::secret_key &view_key = keys.m_view_secret_key;
            const crypto::secret_key &spend_key = keys.m_spend_secret_key;
            std::array<char, sizeof(view_key) + sizeof(spend_key) + 1> data;
            memcpy(data.data(), &view_key, sizeof(view_key));
            memcpy(data.data() + sizeof(view_key), &spend_key, sizeof(spend_key));
            data[sizeof(data) - 1] = config::HASH_KEY_WALLET;
            crypto::generate_chacha_key(data.data(), sizeof(data), key, kdf_rounds);
            return true;
        }

        bool  device_default::get_public_address(cryptonote::account_public_address &pubkey) {
             dfns();
        }
        bool  device_default::get_secret_keys(crypto::secret_key &viewkey , crypto::secret_key &spendkey)  {
             dfns();
        }
        /* ======================================================================= */
        /*                               SUB ADDRESS                               */
        /* ======================================================================= */

        bool device_default::derive_subaddress_public_key
        (
         const crypto::public_key &out_key
         , const crypto::key_derivation &derivation
         , const std::size_t output_index
         , crypto::public_key &derived_key
         ) {
            return crypto::derive_subaddress_public_key(out_key, derivation, output_index,derived_key);
        }

        crypto::public_key device_default::get_subaddress_spend_public_key
        (
         const cryptonote::account_keys& keys
         , const cryptonote::subaddress_index &index
         )
        {
            if (index.is_zero())
              return keys.m_account_address.m_spend_public_key;

            // m = Hs(a || index_major || index_minor)
            const crypto::secret_key m = get_subaddress_secret_key(keys.m_view_secret_key, index);

            // M = m*G
            const crypto::public_key M = crypto::p2pk(crypto::multBase(m));

            // D = B + M
            return crypto::p2pk(keys.m_account_address.m_spend_public_key + M);
        }

        std::vector<crypto::public_key> device_default::get_subaddress_spend_public_keys
        (
         const cryptonote::account_keys &keys
         , uint32_t account
         , uint32_t begin
         , uint32_t end
         )
        {
            LOG_ERROR_AND_THROW_UNLESS(begin <= end, "begin > end");

            std::vector<crypto::public_key> pkeys;
            pkeys.reserve(end - begin);
            cryptonote::subaddress_index index = {account, begin};

            const auto public_spend_key = keys.m_account_address.m_spend_public_key;
            if (!is_valid_point(public_spend_key)) {
              LOG_FATAL("public spend key is not on the main group");
            }


            for (uint32_t idx = begin; idx < end; ++idx)
            {
                index.minor = idx;
                if (index.is_zero())
                {
                    pkeys.push_back(keys.m_account_address.m_spend_public_key);
                    continue;
                }
                crypto::secret_key m = get_subaddress_secret_key(keys.m_view_secret_key, index);

                // M = m*G
                const crypto::ec_point mG = crypto::multBase(m);

                // D = B + M
                const crypto::public_key D = crypto::p2pk(public_spend_key + mG);

                pkeys.push_back(D);
            }
            return pkeys;
        }

        cryptonote::account_public_address device_default::get_subaddress(const cryptonote::account_keys& keys, const cryptonote::subaddress_index &index) {
            if (index.is_zero())
              return keys.m_account_address;

            crypto::public_key D = get_subaddress_spend_public_key(keys, index);

            // C = a*D
            crypto::public_key C = rct::rct_p2pk
              (rct::multP(rct::pk2rct_p(D), rct::sk2rct_s(keys.m_view_secret_key)));

            // result: (C, D)
            cryptonote::account_public_address address;
            address.m_view_public_key  = C;
            address.m_spend_public_key = D;
            return address;
        }

        crypto::secret_key device_default::get_subaddress_secret_key(const crypto::secret_key &a, const cryptonote::subaddress_index &index) {
          const uint32_t major_i = SWAP32LE(index.major);
          const uint32_t minor_i = SWAP32LE(index.minor);
          const epee::blob::data major = epee::blob::data((uint8_t*)&major_i, sizeof(uint32_t));
          const epee::blob::data minor = epee::blob::data((uint8_t*)&minor_i, sizeof(uint32_t));


          // here trailing 0 is part of the HASH_KEY ..
          const epee::blob::data hashData =
            epee::blob::data((const uint8_t*)config::HASH_KEY_SUBADDRESS, sizeof(config::HASH_KEY_SUBADDRESS))
            + epee::blob::data(a.data.begin(), a.data.size())
            + major
            + minor;

          return s2sk(crypto::hash_to_scalar(hashData));
        }

        /* ======================================================================= */
        /*                            DERIVATION & KEY                             */
        /* ======================================================================= */

        bool  device_default::verify_keys(const crypto::secret_key &secret_key, const crypto::public_key &public_key) {
            crypto::public_key calculated_pub;
            bool r = crypto::secret_key_to_public_key(secret_key, calculated_pub);
            return r && public_key == calculated_pub;
        }

        bool device_default::multP(rct::rct_point & aP, const rct::rct_point &P, const rct::rct_scalar &a) {
            aP = rct::multP(P,a);
            return true;
        }

        bool device_default::multG(rct::rct_point &aG, const rct::rct_scalar &a) {
            aG = rct::multG(a);
            return true;
        }

        bool device_default::sc_secret_add(crypto::secret_key &r, const crypto::secret_key &a, const crypto::secret_key &b) {
            r = crypto::s2sk(a + b);
            return true;
        }

        crypto::secret_key  device_default::generate_keys
        (
         crypto::public_key &pub
         , const std::optional<crypto::secret_key> recovery_key
         )
        {
          crypto::secret_key k;
          std::tie(k, pub) = crypto::generate_keys(recovery_key);
          return k;
        }

        bool device_default::generate_key_derivation(const crypto::public_key &key1, const crypto::secret_key &key2, crypto::key_derivation &derivation) {
            return crypto::generate_key_derivation(key1, key2, derivation);
        }

        bool device_default::hash_derivation_to_scalar(const crypto::key_derivation &derivation, const size_t output_index, crypto::ec_scalar &res){
            res = crypto::hash_derivation_to_scalar(derivation,output_index);
            return true;
        }

        bool device_default::derive_secret_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::secret_key &base, crypto::secret_key &derived_key){
            derived_key = crypto::derive_secret_key(derivation, output_index, base);
            return true;
        }

        bool device_default::derive_public_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::public_key &base, crypto::public_key &derived_key){
            return crypto::derive_public_key(derivation, output_index, base, derived_key);
        }

        bool device_default::secret_key_to_public_key(const crypto::secret_key &sec, crypto::public_key &pub) {
            return crypto::secret_key_to_public_key(sec,pub);
        }

        crypto::key_image device_default::generate_key_image(const crypto::public_key &pub, const crypto::secret_key &sec){
            return crypto::generate_key_image(pub, sec);
        }

        bool device_default::conceal_derivation(crypto::key_derivation &derivation, const crypto::public_key &tx_pub_key, const std::vector<crypto::public_key> &additional_tx_pub_keys, const crypto::key_derivation &main_derivation, const std::vector<crypto::key_derivation> &additional_derivations){
            return true;
        }

        /* ======================================================================= */
        /*                               TRANSACTION                               */
        /* ======================================================================= */
        void device_default::generate_tx_proof(const crypto::hash &prefix_hash,
                                               const crypto::public_key &R, const crypto::public_key &A, const std::optional<crypto::public_key> &B, const crypto::public_key &D, const crypto::secret_key &r,
                                               crypto::signature &sig) {
            sig = crypto::generate_tx_proof(prefix_hash, R, A, B, D, r);
        }

        bool device_default::open_tx(crypto::secret_key &tx_key) {
            cryptonote::keypair txkey = cryptonote::keypair::generate(*this);
            tx_key = txkey.sec;
            return true;
        }

        void device_default::get_transaction_prefix_hash(const cryptonote::transaction_prefix& tx, crypto::hash& h) {
            cryptonote::get_transaction_prefix_hash(tx, h);
        }

        bool device_default::generate_output_ephemeral_keys
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
         )
        {
            crypto::key_derivation derivation;

            // make additional tx pubkey if necessary
            cryptonote::keypair additional_txkey;
            if (need_additional_txkeys)
            {
                additional_txkey.sec = additional_tx_keys[output_index];
                if (dst_entr.is_subaddress)
                    additional_txkey.pub = rct::rct_p2pk(rct::multP(rct::pk2rct_p(dst_entr.addr.m_spend_public_key), rct::sk2rct_s(additional_txkey.sec)));
                else
                    additional_txkey.pub = rct::rct_p2pk(rct::multG(rct::sk2rct_s(additional_txkey.sec)));
            }

            bool r;
            if (change_addr && dst_entr.addr == *change_addr)
            {
            // sending change to yourself; derivation = a*R
                r = generate_key_derivation(txkey_pub, sender_account_keys.m_view_secret_key, derivation);
                LOG_ERROR_AND_RETURN_UNLESS(r, false, "at creation outs: failed to generate_key_derivation(" << txkey_pub << ", " << sender_account_keys.m_view_secret_key << ")");
            }
            else
            {
            // sending to the recipient; derivation = r*A (or s*C in the subaddress scheme)
                r = generate_key_derivation(dst_entr.addr.m_view_public_key, dst_entr.is_subaddress && need_additional_txkeys ? additional_txkey.sec : tx_key, derivation);
                LOG_ERROR_AND_RETURN_UNLESS(r, false, "at creation outs: failed to generate_key_derivation(" << dst_entr.addr.m_view_public_key << ", " << (dst_entr.is_subaddress && need_additional_txkeys ? additional_txkey.sec : tx_key) << ")");
            }

            if (need_additional_txkeys)
            {
                additional_tx_public_keys.push_back(additional_txkey.pub);
            }

            if (tx_version > 1)
            {
                rct::rct_scalar scalar1;
                hash_derivation_to_scalar(derivation, output_index, scalar1);
                amount_keys.push_back(scalar1);
            }
            r = derive_public_key(derivation, output_index, dst_entr.addr.m_spend_public_key, out_eph_public_key);
            LOG_ERROR_AND_RETURN_UNLESS(r, false, "at creation outs: failed to derive_public_key(" << derivation << ", " << output_index << ", "<< dst_entr.addr.m_spend_public_key << ")");

            return r;
        }

        rct::rct_scalar device_default::genCommitmentMask(const crypto::crypto_data &amount_key) {
            return rct::genCommitmentMask(amount_key);
        }

        bool  device_default::ecdhEncode(rct::ecdhTuple & unmasked, const rct::rct_scalar & sharedSec) {
            unmasked = rct::ecdhEncode(unmasked.amount, sharedSec);
            return true;
        }

        bool  device_default::ecdhDecode(rct::ecdhTuple & masked, const rct::rct_scalar & sharedSec) {
            masked = rct::ecdhDecode(masked.amount, sharedSec);
            return true;
        }

        bool  device_default::mlsag_pre_hash
        (
        const std::string &blob
        , size_t inputs_size
        , size_t outputs_size
        , const crypto::dataV &hashes
        , const rct::ct_public_keyV &outPk
        , crypto::hash &prehash
        )
        {
            prehash = rct::hash_keys(hashes);
            return true;
        }

        bool device_default::clsag_prepare
        (
         const rct::rct_scalar &p
         , const rct::rct_scalar &z
         , rct::rct_point &I
         , rct::rct_point &D
         , const rct::rct_point &H
         , rct::rct_scalar &a
         , rct::rct_point &aG
         , rct::rct_point &aH
         ) {
            std::tie(a, aG) = rct::skpkGen(); // aG = a*G
            aH = rct::multP(H, a); // aH = a*H
            I = rct::multP(H, p); // I = p*H
            D = rct::multP(H, z); // D = z*H
            return true;
        }

        rct::rct_scalar device_default::clsag_hash(const crypto::dataS data) {
            return rct::hash_keys_to_scalar(data);
        }

        bool device_default::clsag_sign
        (
          const rct::rct_scalar &c
            , const rct::rct_scalar &a
            , const rct::rct_scalar &p
            , const rct::rct_scalar &z
            , const rct::rct_scalar &mu_P
            , const rct::rct_scalar &mu_C
            , rct::rct_scalar &s
         )
        {
            rct::rct_scalar s0_p_mu_P;
            s0_p_mu_P = mu_P * p;
            rct::rct_scalar s0_add_z_mu_C;
            s0_add_z_mu_C = mu_C * z + s0_p_mu_P;
            s = a - c * s0_add_z_mu_C;

            return true;
        }

        bool device_default::close_tx() {
            return true;
        }


        /* ---------------------------------------------------------- */
        static device_default *default_core_device = NULL;
        void register_all(std::map<std::string, std::unique_ptr<device>> &registry) {
            if (!default_core_device) {
                default_core_device = new device_default();
                default_core_device->set_name("default_core_device");

            }
            registry.insert(std::make_pair("default", std::unique_ptr<device>(default_core_device)));
        }


    }

}
