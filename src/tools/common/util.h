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

#include <cstring>
#include <optional>
#include <csignal>
#include <functional>
#include <string>
#include <mutex>

#include <boost/multiprecision/cpp_int.hpp>

namespace tools
{
  /*! \brief creates directories for a path
   *
   *  wrapper around boost::filesyste::create_directories.
   *  (ensure-directory-exists): greenspun's tenth rule in action!
   */
  bool create_directories_if_necessary(const std::string& path);
  /*! \brief std::rename wrapper for nix and something strange for windows.
   */
  std::error_code replace_file(const std::string& old_name, const std::string& new_name);

  bool on_startup();

  void signal_handler_install(std::function<void(int)> f);

  void set_strict_default_file_permissions(bool strict);

  void set_max_concurrency(unsigned n);
  unsigned get_max_concurrency();

  std::optional<std::pair<uint32_t, uint32_t>> parse_subaddress_lookahead(const std::string& str);

  std::string get_human_readable_timestamp(uint64_t ts);

  std::string get_human_readable_timespan(uint64_t seconds);

  std::string get_human_readable_unit
  (
   const boost::multiprecision::cpp_int bytes
   , const std::string unit
   , const boost::multiprecision::cpp_int k
   );

  std::string get_human_readable_bytes
  (
   const boost::multiprecision::cpp_int bytes
   );

  std::string get_human_readable_number
  (
   const boost::multiprecision::cpp_int bytes
   );
}
