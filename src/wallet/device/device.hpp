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

#include "math/ringct/functional/rctTypes.hpp"

#include "math/crypto/controller/chacha.hpp"

#include "config/cryptonote.hpp"

#include <memory>


#ifndef USE_DEVICE_LEDGER
#define USE_DEVICE_LEDGER 1
#endif

#if !defined(HAVE_HIDAPI)
#undef  USE_DEVICE_LEDGER
#define USE_DEVICE_LEDGER 0
#endif

#if USE_DEVICE_LEDGER
#define WITH_DEVICE_LEDGER
#endif

// forward declaration needed because this header is included by headers in libcryptonote_basic which depends on libdevice
namespace cryptonote
{
    struct account_public_address;
    struct account_keys;
    struct subaddress_index;
    struct tx_destination_entry;
    struct keypair;
    class transaction_prefix;
}

namespace hw {
    namespace {
        //device funcion not supported
        #define dfns()  \
           throw std::runtime_error(std::string("device function not supported: ")+ std::string(__FUNCTION__) + \
                                    std::string(" (device.hpp line ")+std::to_string(__LINE__)+std::string(").")); \
           return false;
    }

    class device_progress {
    public:
      virtual double progress() const { return 0; }
      virtual bool indeterminate() const { return false; }
    };

    class device {
    protected:
        std::string  name;

    public:

        device(): mode(NONE)  {}
        device(const device &hwdev) {}
        virtual ~device()   {}

        explicit virtual operator bool() const = 0;
        enum device_mode {
            NONE,
            TRANSACTION_CREATE_REAL,
            TRANSACTION_CREATE_FAKE,
            TRANSACTION_PARSE
        };
        enum device_type
        {
          SOFTWARE = 0,
          LEDGER = 1,
          TREZOR = 2
        };


        enum device_protocol_t {
            PROTOCOL_DEFAULT,
            PROTOCOL_PROXY,     // Originally defined by Ledger
            PROTOCOL_COLD,      // Originally defined by Trezor
        };

        /* ======================================================================= */
        /*                              SETUP/TEARDOWN                             */
        /* ======================================================================= */
        virtual bool set_name(const std::string &name) = 0;
        virtual const std::string get_name() const = 0;

        virtual  bool init(void) = 0;
        virtual bool release() = 0;

        virtual bool connect(void) = 0;
        virtual bool disconnect(void) = 0;

        virtual bool set_mode(device_mode mode) { this->mode = mode; return true; }
        virtual device_mode get_mode() const { return mode; }

        virtual device_type get_type() const = 0;

        virtual device_protocol_t device_protocol() const { return PROTOCOL_DEFAULT; };
        virtual void set_derivation_path(const std::string &derivation_path) {};

        virtual void set_pin(const epee::wipeable_string & pin) {}
        virtual void set_passphrase(const epee::wipeable_string & passphrase) {}

        /* ======================================================================= */
        /*  LOCKER                                                                 */
        /* ======================================================================= */
        virtual void lock(void) = 0;
        virtual void unlock(void) = 0;
        virtual bool try_lock(void) = 0;


        /* ======================================================================= */
        /*                             WALLET & ADDRESS                            */
        /* ======================================================================= */

        /* ======================================================================= */
        /*                               SUB ADDRESS                               */
        /* ======================================================================= */
        virtual crypto::public_key  get_subaddress_spend_public_key(const cryptonote::account_keys& keys, const cryptonote::subaddress_index& index) = 0;
        virtual std::vector<crypto::public_key>  get_subaddress_spend_public_keys(const cryptonote::account_keys &keys, uint32_t account, uint32_t begin, uint32_t end) = 0;
        virtual cryptonote::account_public_address  get_subaddress(const cryptonote::account_keys& keys, const cryptonote::subaddress_index &index) = 0;
        virtual crypto::secret_key  get_subaddress_secret_key(const crypto::secret_key &sec, const cryptonote::subaddress_index &index) = 0;

        /* ======================================================================= */
        /*                            DERIVATION & KEY                             */
        /* ======================================================================= */
        virtual bool  verify_keys(const crypto::secret_key &secret_key, const crypto::public_key &public_key) = 0;

        /* ======================================================================= */
        /*                               TRANSACTION                               */
        /* ======================================================================= */

        virtual bool  generate_output_ephemeral_keys
        (
         const size_t tx_version
         , const cryptonote::account_keys &sender_account_keys
         , const crypto::public_key &txkey_pub
         , const crypto::secret_key &tx_key
         , const cryptonote::tx_destination_entry &dst_entr
         , const std::optional<cryptonote::account_public_address> &change_addr
         , const size_t output_index
         , const bool &need_additional_txkeys
         , const std::vector<crypto::secret_key> &additional_tx_keys
         , std::vector<crypto::public_key> &additional_tx_public_keys
         , rct::rct_scalarV &amount_keys
         , crypto::public_key &out_eph_public_key
         ) = 0;


        virtual bool clsag_prepare
        (
         const rct::rct_scalar &p
         , const rct::rct_scalar &z
         , rct::rct_point &I
         , rct::rct_point &D
         , const rct::rct_point &H
         , rct::rct_scalar &a
         , rct::rct_point &aG
         , rct::rct_point &aH
         ) = 0;
        virtual rct::rct_scalar clsag_hash(const crypto::dataS data) = 0;
        virtual bool clsag_sign
        (
         const rct::rct_scalar &c
         , const rct::rct_scalar &a
         , const rct::rct_scalar &p
         , const rct::rct_scalar &z
         , const rct::rct_scalar &mu_P
         , const rct::rct_scalar &mu_C
         , rct::rct_scalar &s
         ) = 0;

        virtual bool  has_ki_cold_sync(void) const { return false; }
        virtual bool  has_tx_cold_sign(void) const { return false; }
        virtual bool  has_ki_live_refresh(void) const { return true; }
        virtual bool  compute_key_image(const cryptonote::account_keys& ack, const crypto::public_key& out_key, const crypto::key_derivation& recv_derivation, size_t real_output_index, const cryptonote::subaddress_index& received_index, cryptonote::keypair& in_ephemeral, crypto::key_image& ki) { return false; }
        virtual void  computing_key_images(bool started) {};
        virtual void  set_network_type(cryptonote::network_type network_type) { }
        virtual void  display_address(const cryptonote::subaddress_index& index) {}

    protected:
        device_mode mode;
    } ;

    struct reset_mode {
        device& hwref;
        reset_mode(hw::device& dev) : hwref(dev) { }
        ~reset_mode() { hwref.set_mode(hw::device::NONE);}
    };

    class device_registry {
    private:
      std::map<std::string, std::unique_ptr<device>> registry;

    public:
      device_registry();
      bool register_device(const std::string & device_name, device * hw_device);
      device& get_device(const std::string & device_descriptor);
    };

    device& get_device(const std::string & device_descriptor);
    bool register_device(const std::string & device_name, device * hw_device);
}

