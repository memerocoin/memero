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


#include "keys_unlocker.hpp"

#include "string_tools.h"
#include "file_io_utils.h"

namespace wallet {
namespace logic {
namespace controller {
namespace keys_unlocker {

  std::mutex wallet_keys_unlocker::lockers_lock;
  unsigned int wallet_keys_unlocker::lockers = 0;

  wallet_keys_unlocker::wallet_keys_unlocker
  (
   tools::wallet2 &w
   , const std::optional<tools::password_container> &password
   ):
    w(w),
    locked(password != std::nullopt)
  {
    std::lock_guard<std::mutex> lock(lockers_lock);
    if (lockers++ > 0)
      locked = false;
    if (!locked || w.is_unattended()
        || w.ask_password() != tools::wallet2::AskPasswordToDecrypt || w.watch_only())
    {
      locked = false;
      return;
    }
    const epee::wipeable_string pass = password->password();
    w.generate_chacha_key_from_password(pass, key);
    w.decrypt_keys(key);
  }

  wallet_keys_unlocker::wallet_keys_unlocker
  (
   tools::wallet2 &w
   , bool locked
   , const epee::wipeable_string &password
   ):
    w(w),
    locked(locked)
  {
    std::lock_guard<std::mutex> lock(lockers_lock);
    if (lockers++ > 0)
      locked = false;
    if (!locked)
      return;
    w.generate_chacha_key_from_password(password, key);
    w.decrypt_keys(key);
  }

  wallet_keys_unlocker::~wallet_keys_unlocker()
  {
    try
    {
      std::lock_guard<std::mutex> lock(lockers_lock);
      if (lockers == 0)
      {
        MERROR("There are no lockers in wallet_keys_unlocker dtor");
        return;
      }
      --lockers;
      if (!locked)
        return;
      w.encrypt_keys(key);
    }
    catch (...)
    {
      MERROR("Failed to re-encrypt wallet keys");
      // do not propagate through dtor, we'd crash
    }
  }

} // keys_unlocker
} // controller
} // logic
} // wallet
