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

#include <openssl/pem.h> // pem_write

#include "string_tools.h"
#include "file_io_utils.h"

#include "config/lol.hpp"

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
    keys_file = file_path;
    wallet_file = file_path;
    std::error_code e;
    if(epee::string_tools::get_extension(keys_file) == "keys")
    {//provided keys file name
      wallet_file = epee::string_tools::cut_off_extension(wallet_file);
    } else
    {//provided wallet file name
      keys_file += ".keys";
    }
  }


  bool save_to_file
  (
   const std::string& path_to_file
   , const std::string& raw
   , const bool is_printable
   )
  {
    if (is_printable)
    {
      return epee::file_io_utils::save_string_to_file(path_to_file, raw);
    }

    FILE *fp = fopen(path_to_file.c_str(), "w+");
    if (!fp)
    {
      MERROR("Failed to open wallet file for writing: " << path_to_file << ": " << strerror(errno));
      return false;
    }

    // Save the result b/c we need to close the fp before returning success/failure.
    int write_result = PEM_write(fp, config::lol::ASCII_OUTPUT_MAGIC.c_str(),
                                 "", (const unsigned char *) raw.c_str(), raw.length());
    fclose(fp);

    if (write_result == 0)
    {
      return false;
    }
    else
    {
      return true;
    }
  }

} // wallet
} // controller
} // logic
} // wallet
