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


#include "wallet.hpp"

#include "wallet/logic/type/wallet.hpp"
#include "wallet/logic/type/transfer.hpp"
#include "wallet/logic/functional/wallet.hpp"
#include "wallet/logic/functional/helper.hpp"

#include "wallet/device/functional/device_default.hpp"

#include "wallet/api/wallet_errors.h"

#include <rapidjson/document.h>
#include <rapidjson/writer.h>

#include "tools/epee/include/string_tools.h"
#include "tools/epee/include/file_io_utils.h"
#include "tools/epee/include/storages/portable_storage_template_helper.h"
#include "tools/serialization/binary_utils.h"
#include "tools/common/json_util.h"

#include "math/crypto/controller/random.hpp"

#include <cstdint>


namespace wallet {
namespace logic {
namespace controller {
namespace wallet {

  void do_prepare_file_names
  (
   const std::string& file_path
   , std::string& keys_file
   , std::string& wallet_file
   )
  {
    std::error_code e;
    if(std::filesystem::path(file_path).extension() == ".keys")
    {
      //provided keys file name
      keys_file = file_path;
      wallet_file = std::filesystem::path(file_path).replace_extension("");
    } else
    {
      //provided wallet file name
      keys_file = file_path + ".keys";
      wallet_file = file_path;
    }
  }


  bool save_to_file
  (
   const std::string& path_to_file
   , const std::string& raw
   )
  {
    return epee::file_io_utils::save_string_to_file(path_to_file, raw);
  }

  bool load_from_file
  (
   const std::string& path_to_file
   , std::string& target_str
   , const size_t max_size
   )
  {
    return epee::file_io_utils::load_file_to_string(path_to_file, target_str, max_size);
  }

  void print_source_entry(const cryptonote::tx_source_entry& src)
  {
    std::string indexes;
    std::for_each
      (src.outputs.begin(), src.outputs.end(),
       [&](const cryptonote::tx_source_entry::output_entry& s_e) {
         indexes += std::to_string(s_e.first) + " ";
       }
       );
    LOG_PRINT_L0("amount=" << cryptonote::print_money(src.amount)
                 << ", real_output=" <<src.real_output
                 << ", real_output_in_tx_index=" << src.real_output_in_tx_index
                 << ", indexes: " << indexes);
  }

  /*!
  * \brief verify password for specified wallet keys file.
  * \param keys_file_name  Keys file to verify password for
  * \param password        Password to verify
  * \param no_spend_key    If set = only verify view keys, otherwise also spend keys
  * \param hwdev           The hardware device to use
  * \return                true if password is correct
  *
  * for verification only
  * should not mutate state, unlike load_keys()
  * can be used prior to rewriting wallet keys file, to ensure user has entered the correct password
  *
  */
  bool verify_password(const std::string& keys_file_name, const epee::wipeable_string& password, bool no_spend_key, uint64_t kdf_rounds)
  {
    rapidjson::Document json;
    ::wallet::logic::type::wallet::keys_file_data keys_file_data;
    std::string buf;
    bool encrypted_secret_keys = false;
    bool r = ::wallet::logic::controller::wallet::load_from_file(keys_file_name, buf);
    THROW_WALLET_EXCEPTION_IF(!r, tools::error::file_read_error, keys_file_name);

    // Decrypt the contents
    r = ::serialization::parse_binary(buf, keys_file_data);
    THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, "internal error: failed to deserialize \"" + keys_file_name + '\"');
    crypto::chacha_key key;
    crypto::generate_chacha_key(password.data(), password.size(), key, kdf_rounds);
    std::string account_data;
    account_data.resize(keys_file_data.account_data.size());
    crypto::chacha20(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);
    json.Parse(account_data.c_str());

    {
      account_data = std::string(json["key_data"].GetString(), json["key_data"].GetString() +
        json["key_data"].GetStringLength());
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, encrypted_secret_keys, uint32_t, Uint, false, false);
      encrypted_secret_keys = field_encrypted_secret_keys;
    }

    cryptonote::account_base account_data_check;

    r = epee::serialization::load_t_from_binary(account_data_check, account_data);

    if (encrypted_secret_keys)
      account_data_check.decrypt_keys(key);

    const cryptonote::account_keys& keys = account_data_check.get_keys();
    r = r && crypto::verify_keys(keys.m_view_secret_key,  keys.m_account_address.m_view_public_key);
    if(!no_spend_key)
      r = r && crypto::verify_keys(keys.m_spend_secret_key, keys.m_account_address.m_spend_public_key);
    return r;
  }

  //----------------------------------------------------------------------------------------------------
  size_t pop_best_value_from(const ::wallet::logic::type::wallet::transfer_container &transfers, std::vector<size_t> &unused_indices, const std::vector<size_t>& selected_transfers, bool smallest)
  {
    std::vector<size_t> candidates;
    float best_relatedness = 1.0f;
    for (size_t n = 0; n < unused_indices.size(); ++n)
    {
      const ::wallet::logic::type::transfer::transfer_details &candidate = transfers[unused_indices[n]];
      float relatedness = 0.0f;
      for (const auto &i: selected_transfers)
      {
        float r = ::wallet::logic::functional::wallet::get_output_relatedness(candidate, transfers[i]);
        if (r > relatedness)
        {
          relatedness = r;
          if (relatedness == 1.0f)
            break;
        }
      }

      if (relatedness < best_relatedness)
      {
        best_relatedness = relatedness;
        candidates.clear();
      }

      if (relatedness == best_relatedness)
        candidates.push_back(n);
    }

    // we have all the least related outputs in candidates, so we can pick either
    // the smallest, or a random one, depending on request
    size_t idx;
    if (smallest)
    {
      idx = 0;
      for (size_t n = 0; n < candidates.size(); ++n)
      {
        const transfer_details &td = transfers[unused_indices[candidates[n]]];
        if (td.amount() < transfers[unused_indices[candidates[idx]]].amount())
          idx = n;
      }
    }
    else
    {
      idx = crypto::rand_idx(candidates.size());
    }
    return pop_index (unused_indices, candidates[idx]);
  }
} // wallet
} // controller
} // logic
} // wallet
