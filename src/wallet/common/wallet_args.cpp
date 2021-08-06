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

#include "wallet_args.h"


#include "tools/common/util.h"

#include "config/version.hpp"

#include <filesystem>
#include <boost/format.hpp>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.wallet2"

// workaround for a suspected bug in pthread/kernel on MacOS X
#ifdef __APPLE__
#define DEFAULT_MAX_CONCURRENCY 1
#else
#define DEFAULT_MAX_CONCURRENCY 0
#endif

namespace
{
  class Print
  {
  public:
    Print(const std::function<void(const std::string&, bool)> &p, bool em = false): print(p), emphasis(em) {}
    ~Print() { print(ss.str(), emphasis); }
    template<typename T> std::ostream &operator<<(const T &t) { ss << t; return ss; }
  private:
    const std::function<void(const std::string&, bool)> &print;
    std::stringstream ss;
    bool emphasis;
  };
}

namespace wallet_args
{
  // Create on-demand to prevent static initialization order fiasco issues.
  command_line::arg_descriptor<std::string> arg_wallet_file()
  {
    return {"open", wallet_args::tr("Use wallet <arg>"), ""};
  }

  const char* tr(const char* str)
  {
    return str;
  }

  std::pair<std::optional<boost::program_options::variables_map>, bool> main
  (
    int argc, char** argv,
    const char* const usage,
    const std::string notice,
    boost::program_options::options_description desc_params,
    const boost::program_options::positional_options_description& positional_options,
    const std::function<void(const std::string&, bool)> &print
   )
  {
    namespace bf = std::filesystem;
    namespace po = boost::program_options;

    const command_line::arg_descriptor<std::string> arg_log_level = {"log-level", "0-4", ""};
    const command_line::arg_descriptor<uint32_t> arg_max_concurrency = {"max-concurrency", wallet_args::tr("Max number of threads to use for a parallel job"), DEFAULT_MAX_CONCURRENCY};
    const command_line::arg_descriptor<std::string> arg_config_file = {
      "config-file"
      , "Config file"
      , ""
      , true
    };


    tools::on_startup();
#ifdef NDEBUG
    tools::disable_core_dumps();
#endif
    tools::set_strict_default_file_permissions(true);

    po::options_description desc_general(wallet_args::tr("General options"));
    command_line::add_arg(desc_general, command_line::arg_help);
    command_line::add_arg(desc_general, command_line::arg_version);

    command_line::add_arg(desc_params, arg_log_level);
    command_line::add_arg(desc_params, arg_max_concurrency);
    command_line::add_arg(desc_params, arg_config_file);

    po::options_description desc_all;
    desc_all.add(desc_general).add(desc_params);
    po::variables_map vm;
    bool should_terminate = false;
    bool r = command_line::handle_error_helper(desc_all, [&]()
    {
      auto parser = po::command_line_parser(argc, argv).options(desc_all).positional(positional_options);
      po::store(parser.run(), vm);

      if (command_line::get_arg(vm, command_line::arg_help))
      {
        Print(print) << "Lolnero '" << LOLNERO_RELEASE_NAME << "' (v" << LOLNERO_VERSION_FULL << ")" << std::endl;
        Print(print) << wallet_args::tr("This is the command line lolnero wallet. It needs to connect to a lolnero\n"
												  "daemon to work correctly.") << std::endl;
        Print(print) << wallet_args::tr("Usage:") << std::endl << "  " << usage;
        Print(print) << desc_all;
        should_terminate = true;
        return true;
      }
      else if (command_line::get_arg(vm, command_line::arg_version))
      {
        Print(print) << "Lolnero '" << LOLNERO_RELEASE_NAME << "' (v" << LOLNERO_VERSION_FULL << ")";
        should_terminate = true;
        return true;
      }

      if(command_line::has_arg(vm, arg_config_file))
      {
        std::string config = command_line::get_arg(vm, arg_config_file);
        bf::path config_path(config);
        std::error_code ec;
        if (bf::exists(config_path, ec))
        {
          po::store(po::parse_config_file<char>(config_path.c_str(), desc_params), vm);
        }
        else
        {
          LOG_ERROR(wallet_args::tr("Can't find config file ") << config);
          return false;
        }
      }

      po::notify(vm);
      return true;
    });
    if (!r)
      return {std::nullopt, true};

    if (should_terminate)
      return {std::move(vm), should_terminate};

    std::string log_path;
    if (!command_line::is_arg_defaulted(vm, arg_log_level))
    {
      epee::mlog_set_log(command_line::get_arg(vm, arg_log_level));
    }

    if (!notice.empty())
      Print(print) << notice << std::endl;

    if (!command_line::is_arg_defaulted(vm, arg_max_concurrency))
      tools::set_max_concurrency(command_line::get_arg(vm, arg_max_concurrency));

    Print(print) << "Lolnero '" << LOLNERO_RELEASE_NAME << "' (v" << LOLNERO_VERSION_FULL << ")";

    if (!command_line::is_arg_defaulted(vm, arg_log_level))
      LOG_INFO("Setting log level = " << command_line::get_arg(vm, arg_log_level));
    else
    {
      const char *logs = getenv("MONERO_LOGS");
      LOG_INFO("Setting log levels = " << (logs ? logs : "<default>"));
    }

    return {std::move(vm), should_terminate};
  }
}
