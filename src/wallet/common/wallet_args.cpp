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

#include "daemon/cli/daemon_common.hpp"

#include "config/version/version.hpp"

#include <filesystem>
#include <boost/format.hpp>




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

    tools::on_startup();
    tools::set_strict_default_file_permissions(true);

    po::options_description desc_general(wallet_args::tr("General options"));
    command_line::add_arg(desc_general, command_line::arg_help);
    command_line::add_arg(desc_general, command_line::arg_version);

    command_line::add_arg(desc_params, daemon_common::arg_log_level);
    command_line::add_arg(desc_params, daemon_common::arg_max_concurrency);

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
        Print(print) << wallet_args::tr("Usage:") << std::endl << "  " << usage;
        Print(print) << desc_all;
        should_terminate = true;
        return true;
      }
      else if (command_line::get_arg(vm, command_line::arg_version))
      {
        daemon_common::show_version();
        should_terminate = true;
        return true;
      }

      po::notify(vm);
      return true;
    });
    if (!r)
      return {std::nullopt, true};

    if (should_terminate)
      return {std::move(vm), should_terminate};

    if (!notice.empty())
      Print(print) << notice << std::endl;

    if (
        !command_line::is_arg_defaulted
        (
         vm
         , daemon_common::arg_max_concurrency
         )
        ) {
      tools::set_max_concurrency
        (command_line::get_arg(vm, daemon_common::arg_max_concurrency));
    }

    daemon_common::show_version();

    if (!command_line::is_arg_defaulted(vm, daemon_common::arg_log_level)) {
      const auto log_level = 
        (command_line::get_arg(vm, daemon_common::arg_log_level));

      epee::set_log_level_from_string(log_level);

      LOG_INFO("Setting log level = " + log_level);
    }

    return {std::move(vm), should_terminate};
  }
}
