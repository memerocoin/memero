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

#include "util.h"

#include "tools/epee/include/logging.hpp"
#include "tools/epee/include/misc_os_dependent.h"

#include "tools/epee/include/net/http_client.h"                        // epee::net_utils::...

#include "config/cryptonote.hpp"

#include <boost/format.hpp>




namespace tools
{
  std::function<void(int)> signal_handler::m_handler;

  std::string get_default_data_dir()
  {
    std::string config_folder;

    std::string pathRet;
    char* pszHome = getenv("HOME");
    if (pszHome == NULL || strlen(pszHome) == 0)
      pathRet = "/";
    else
      pathRet = pszHome;
    config_folder = (pathRet + "/." + std::string(config::lol::CRYPTONOTE_NAME));

    return config_folder;
  }

  bool create_directories_if_necessary(const std::string& path)
  {
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path fs_path(path);
    if (fs::is_directory(fs_path, ec))
    {
      return true;
    }

    bool res = fs::create_directories(fs_path, ec);
    if (res)
    {
      LOG_PRINT_L2("Created directory: " << path);
    }
    else
    {
      LOG_PRINT_L2("Can't create directory: " << path << ", err: "<< ec.message());
    }

    return res;
  }

  std::error_code replace_file(const std::string& old_name, const std::string& new_name)
  {
    int code;
    bool ok = 0 == std::rename(old_name.c_str(), new_name.c_str());
    code = ok ? 0 : errno;
    return std::error_code(code, std::system_category());
  }

  bool on_startup()
  {
    OPENSSL_init_ssl(0, NULL);

    return true;
  }

  void set_strict_default_file_permissions(bool strict)
  {
    mode_t mode = strict ? 077 : 0;
    umask(mode);
  }

  std::atomic<unsigned int> max_concurrency = std::thread::hardware_concurrency();

  void set_max_concurrency(unsigned n)
  {
    if (n < 1)
      n = std::thread::hardware_concurrency();
    unsigned hwc = std::thread::hardware_concurrency();
    if (n > hwc)
      n = hwc;

    max_concurrency = n;
  }

  unsigned get_max_concurrency()
  {
    return max_concurrency;
  }

  bool is_local_address(const std::string &address)
  {
    // always assume Tor/I2P addresses to be untrusted by default
    if (boost::ends_with(address, ".onion") || boost::ends_with(address, ".i2p"))
    {
      LOG_DEBUG("Address '" << address << "' is Tor/I2P, non local");
      return false;
    }

    // extract host
    epee::net_utils::http::url_content u_c;
    if (!epee::net_utils::parse_url(address, u_c))
    {
      LOG_WARNING("Failed to determine whether address '" << address << "' is local, assuming not");
      return false;
    }
    if (u_c.host.empty())
    {
      LOG_WARNING("Failed to determine whether address '" << address << "' is local, assuming not");
      return false;
    }

    // resolve to IP
    boost::asio::io_service io_service;
    boost::asio::ip::tcp::resolver resolver(io_service);
    boost::asio::ip::tcp::resolver::query query(u_c.host, "");
    boost::asio::ip::tcp::resolver::iterator i = resolver.resolve(query);
    while (i != boost::asio::ip::tcp::resolver::iterator())
    {
      const boost::asio::ip::tcp::endpoint &ep = *i;
      if (ep.address().is_loopback())
      {
        LOG_DEBUG("Address '" << address << "' is local");
        return true;
      }
      ++i;
    }

    LOG_DEBUG("Address '" << address << "' is not local");
    return false;
  }

  std::optional<std::pair<uint32_t, uint32_t>> parse_subaddress_lookahead(const std::string& str)
  {
    auto pos = str.find(":");
    bool r = pos != std::string::npos;
    uint32_t major;
    r = r && epee::string_tools::get_xtype_from_string(major, str.substr(0, pos));
    uint32_t minor;
    r = r && epee::string_tools::get_xtype_from_string(minor, str.substr(pos + 1));
    if (r)
    {
      return std::make_pair(major, minor);
    }
    else
    {
      return {};
    }
  }

  std::string glob_to_regex(const std::string &val)
  {
    std::string newval;

    bool escape = false;
    for (char c: val)
      {
        if (c == '*')
          newval += escape ? "*" : ".*", escape = false;
        else if (c == '?')
          newval += escape ? "?" : ".", escape = false;
        else if (c == '\\')
          newval += '\\', escape = !escape;
        else
          newval += c, escape = false;
      }
    return newval;
  }

  std::string get_human_readable_timestamp(uint64_t ts)
  {
    char buffer[64];
    if (ts < 1234567890)
      return "<unknown>";
    time_t tt = ts;
    struct tm tm;
    epee::misc_utils::get_gmt_time(tt, tm);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);
    return std::string(buffer);
  }

  std::string get_human_readable_timespan(uint64_t seconds)
  {
    if (seconds < 60)
      return std::to_string(seconds) + " seconds";
    std::stringstream ss;
    ss << std::fixed << std::setprecision(1);
    if (seconds < 3600)
    {
      ss << seconds / 60.f;
      return ss.str() + " minutes";
    }
    if (seconds < 3600 * 24)
    {
      ss << seconds / 3600.f;
      return ss.str() + " hours";
    }
    if (seconds < 3600 * 24 * 30.5f)
    {
      ss << seconds / (3600 * 24.f);
      return ss.str() + " days";
    }
    if (seconds < 3600 * 24 * 365.25f)
    {
      ss << seconds / (3600 * 24 * 30.5f);
      return ss.str() + " months";
    }
    if (seconds < 3600 * 24 * 365.25f * 100)
    {
      ss << seconds / (3600 * 24 * 365.25f);
      return ss.str() + " years";
    }
    return "a long time";
  }

  using namespace boost::multiprecision;

  std::string get_human_readable_bytes(const cpp_int bytes) {
    return get_human_readable_unit(bytes, "B", 1024);
  }

  std::string get_human_readable_number(const cpp_int bytes) {
    return get_human_readable_unit(bytes, "", 1000);
  }

  std::string get_human_readable_unit
  (
   const cpp_int bytes
   , const std::string unit
   , const cpp_int k
   )
  {

    // Use 1024 for "kilo", 1024*1024 for "mega" and so on instead of the more modern and standard-conforming
    // 1000, 1000*1000 and so on, to be consistent with other Monero code that also uses base 2 units
    struct byte_map
    {
        const std::string_view format;
        const cpp_int bytes;
    };

    const std::vector<byte_map> sizes =
      {
        {"%.0f ", k}
        , {"%.2f K", k * k}
        , {"%.2f M", cpp_int(k) * k * k}
        , {"%.2f G", cpp_int(k) * k * k * k}
        , {"%.2f T", cpp_int(k) * k * k * k * k}
        , {"%.2f P", cpp_int(k) * k * k * k * k * k}
        , {"%.2f E", cpp_int(k) * k * k * k * k * k * k}
      };

    const auto iter = std::upper_bound
      (
        sizes.begin()
        , sizes.end()
        , byte_map{"", bytes}
        , [](const auto& x, const auto& y) {
          return x.bytes < y.bytes;
        }
       );

    const byte_map size =
      iter != sizes.end()
      ? *iter
      : sizes.back();

    const cpp_int divisor = size.bytes / k;
    const std::string format = std::string(size.format) + unit;
    const double num = (bytes * 100 / divisor).convert_to<double>() / 100.;
    return (boost::format(format) % num).str();
  }
}
