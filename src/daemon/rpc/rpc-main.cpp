/*

Copyright 2021 fuwa

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.


Parts of this file are originally 
Copyright (c) 2014-2020, The Monero Project

see: etc/other-licenses/monero/LICENSE


Parts of this file are originally 
copyright (c) 2012-2013 The Cryptonote developers

*/

#include "command_line_args.h"

#include "daemon/rpc/daemon.h"
#include "daemon/cli/daemon_common.hpp"

#include "network/rpc/rpc_args.h"
#include "network/rpc/core_rpc_server.h"

#include "config/version/version.hpp"

int main(int argc, char const * argv[])
{
  tools::on_startup();

  namespace po = boost::program_options;

  // Build argument description
  po::options_description all_options("All");
  po::options_description visible_options("Options");
  po::options_description core_settings("Settings");
  po::positional_options_description positional_options;

  command_line::add_arg(visible_options, command_line::arg_help);
  command_line::add_arg(visible_options, command_line::arg_version);

  command_line::add_arg
    (core_settings, daemon_common::arg_log_level);

  command_line::add_arg
    (core_settings, daemon_common::arg_max_concurrency);

  daemonize::t_daemon::init_options(core_settings);

  visible_options.add(core_settings);
  all_options.add(visible_options);

  po::variables_map vm;
  const bool arg_parsed = command_line::handle_error_helper
    (
     visible_options
     , [&]()
     {
       boost::program_options::store
         (
          boost::program_options::command_line_parser(argc, argv)
          .options(all_options).positional(positional_options).run()
          , vm
          );

       return true;
     }
     );

  if (!arg_parsed) return 1;

  if (command_line::get_arg(vm, command_line::arg_help))
    {
      std::cout
        << "Usage: "
        << std::string{argv[0]}
        << " [options|settings]"
        << std::endl
        << std::endl
        << visible_options
        ;

      return 0;
    }

  if (command_line::get_arg(vm, command_line::arg_version))
    {
      daemon_common::show_version();
      return 0;
    }


  // Create data dir if it doesn't exist
  std::filesystem::path data_dir =
    std::filesystem::absolute
    (
     command_line::get_arg(vm, cryptonote::arg_data_dir)
     );

  po::notify(vm);

  // Set log level
  if
    (
     !command_line::is_arg_defaulted
     (
      vm
      , daemon_common::arg_log_level
      )
     )
    {
      epee::mlog_set_log
        (command_line::get_arg(vm, daemon_common::arg_log_level));
    }

  // after logs initialized
  tools::create_directories_if_necessary(data_dir.string());

  if
    (
     !command_line::is_arg_defaulted
     (
      vm
      , daemon_common::arg_max_concurrency
      )
     ) {
    tools::set_max_concurrency
      (command_line::get_arg(vm, daemon_common::arg_max_concurrency));
  }

  // logging is now set up
  LOG_GLOBAL(daemon_common::get_version_string());

  try {
    return daemonize::t_daemon{vm}.run();
  }
  catch (std::exception const & ex)
    {
      LOG_ERROR("Exception in main! " + std::string(ex.what()));
    }
  catch (...)
    {
      LOG_ERROR("Exception in main!");
    }
  return 1;
}
