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

*/


#include "tools/epee/include/logging.hpp"

#include "config/lol.hpp"

#include <unistd.h>
#include <iomanip>
#include <set>
#include <atomic>
#include <filesystem>


namespace epee
{

  std::atomic<int> m_log_level = 0;

  // maps epee style log level to new logging system
  void mlog_set_log_level(int level)
  {
    m_log_level = level;
  }

  void mlog_set_log(const std::string x)
  {
    int level = -1;
    try {
      level = std::stoi(x);
    }
    catch (...) {}

    if (level >= 0 && level <= 4)
      {
        epee::mlog_set_log_level(level);
      }
    else
      {
        LOG_ERROR("Invalid numerical log level: " << x);
      }
  }

  std::atomic<bool> initialized(false);
  std::atomic<bool> is_a_tty(false);

  bool is_stdout_a_tty()
  {
    if (!initialized)
      {
        is_a_tty = (0 != isatty(fileno(stdout)));
        initialized = true;
      }

    return is_a_tty;
  }

  void set_console_color(int color, bool bright)
  {
    if (!is_stdout_a_tty())
      return;

    std::string color_str;

    switch(color)
      {
      case color_default:
        {
          color_str = "37";
        }
        break;
      case epee::console_colors::white:
        {
          color_str = "37";
        }
        break;
      case epee::console_colors::red:
        {
          color_str = "31";
        }
        break;
      case epee::console_colors::green:
        {
          color_str = "32";
        }
        break;

      case epee::console_colors::blue:
        {
          color_str = "34";
        }
        break;

      case epee::console_colors::cyan:
        {
          color_str = "36";
        }
        break;

      case epee::console_colors::magenta:
        {
          color_str = "35";
        }
        break;

      case epee::console_colors::yellow:
        {
          color_str = "33";
        }
        break;
      }

    const std::string bright_str =
      bright
      ? "1"
      : "0"
      ;

    std::cout
      << "\033["
      << bright_str
      << ";"
      << color_str
      << "m";
  }

  void reset_console_color() {
    if (!is_stdout_a_tty())
      return;

    std::cout << "\033[0m";
    std::cout.flush();
  }

  const std::set<std::string> default_cat =
    {std::string(epee::GLOBAL_CATEGORY), "logging", "default"};

  std::mutex g_log_mutex;

  std::atomic<size_t> common_length = 1;

  void log_level_map
  (
   const epee::LogLevel level
   , const std::string_view cat_in
   , const std::string_view x
   )
  {
    const std::string cat = std::string(cat_in);
    const std::filesystem::path p = cat;
    const std::string base_name = std::string(p.stem());

    const size_t base_name_length = base_name.size();

    if (base_name_length > common_length) {
      common_length = base_name_length;
    }

    const size_t leading_spaces_length =
      (common_length - base_name_length) / 2;

    const size_t trailing_spaces_length =
      common_length - base_name_length - leading_spaces_length;

    const std::string leading_spaces(leading_spaces_length, ' ');
    const std::string trailing_spaces(trailing_spaces_length, ' ');
    const std::string centered_cat =
      "[" + leading_spaces + base_name + trailing_spaces + "] ";

    const std::string cat_str = m_log_level == 0 ? "" : centered_cat;

    std::string log_header;
    switch (level) {
    case epee::LogLevel::Fatal:
      log_header = "F";
      break;
    case epee::LogLevel::Error:
      log_header = "E";
      break;
    case epee::LogLevel::Warning:
      log_header = "W";
      break;
    case epee::LogLevel::Info:
      log_header = "I";
      break;
    case epee::LogLevel::Verbose:
      log_header = "V";
      break;
    case epee::LogLevel::Debug:
      log_header = "D";
      break;
    case epee::LogLevel::Trace:
      log_header = "T";
      break;
    case epee::LogLevel::Unknown:
      log_header = "U";
      break;
    default:
      break;
    }

    const auto now = std::chrono::system_clock::now();
    const auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::lock_guard<std::mutex> guard(g_log_mutex);
    constexpr bool log_time = false;
    if (log_time) {
      std::cout
        << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%d %X")
        << " "
        << log_header
        << " "
        << cat_str
        << x
        << std::endl;
    } else {
      std::cout << log_header << " " << cat_str << x << std::endl;
    }
  }

  void log_level_cat
  (
   const epee::LogLevel level
   , const std::string_view cat
   , const std::string_view x
   )
  {
    if (level == epee::LogLevel::Fatal) {
      log_level_map(level, cat, x);
      return;
    }

    switch (m_log_level) {
    case 4:
      log_level_map(level, cat, x);
      break;
    case 3:
      switch(level) {
      case epee::LogLevel::Unknown:
      case epee::LogLevel::Trace:
        break;
      default:
        log_level_map(level, cat, x);
        break;
      }
      break;
    case 2:
      switch(level) {
      case epee::LogLevel::Unknown:
      case epee::LogLevel::Trace:
      case epee::LogLevel::Debug:
        break;
      default:
        log_level_map(level, cat, x);
        break;
      }
      break;
    case 1:
      switch(level) {
      case epee::LogLevel::Unknown:
      case epee::LogLevel::Trace:
      case epee::LogLevel::Debug:
      case epee::LogLevel::Verbose:
        break;
      default:
        log_level_map(level, cat, x);
        break;
      }
      break;
    case 0:
      switch(level) {
      case epee::LogLevel::Unknown:
      case epee::LogLevel::Trace:
      case epee::LogLevel::Debug:
      case epee::LogLevel::Verbose:
        break;
      default:
        if (default_cat.find(std::string(cat)) == default_cat.end()) {
          return;
        }
        log_level_map(level, cat, x);
        break;
      }
      break;
    default:
      break;
    }
  }

} // epee
