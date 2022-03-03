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

bool is_stdout_a_tty()
{
  static std::atomic<bool> initialized(false);
  static std::atomic<bool> is_a_tty(false);

  if (!initialized.load(std::memory_order_acquire))
  {
    is_a_tty = (0 != isatty(fileno(stdout)));
    initialized.store(true, std::memory_order_release);
  }

  return is_a_tty;
}

void set_console_color(int color, bool bright)
{
  if (!is_stdout_a_tty())
    return;

  switch(color)
  {
  case console_color_default:
    {
      if(bright)
        std::cout << "\033[1;37m";
      else
        std::cout << "\033[0m";
    }
    break;
  case console_color_white:
    {
      if(bright)
        std::cout << "\033[1;37m";
      else
        std::cout << "\033[0;37m";
    }
    break;
  case console_color_red:
    {
      if(bright)
        std::cout << "\033[1;31m";
      else
        std::cout << "\033[0;31m";
    }
    break;
  case console_color_green:
    {
      if(bright)
        std::cout << "\033[1;32m";
      else
        std::cout << "\033[0;32m";
    }
    break;

  case console_color_blue:
    {
      if(bright)
        std::cout << "\033[1;34m";
      else
        std::cout << "\033[0;34m";
    }
    break;

  case console_color_cyan:
    {
      if(bright)
        std::cout << "\033[1;36m";
      else
        std::cout << "\033[0;36m";
    }
    break;

  case console_color_magenta:
    {
      if(bright)
        std::cout << "\033[1;35m";
      else
        std::cout << "\033[0;35m";
    }
    break;

  case console_color_yellow:
    {
      if(bright)
        std::cout << "\033[1;33m";
      else
        std::cout << "\033[0;33m";
    }
    break;

  }
}

void reset_console_color() {
  if (!is_stdout_a_tty())
    return;

  std::cout << "\033[0m";
  std::cout.flush();
}

const std::set<std::string> default_cat = {"global", "logging", "default"};
std::mutex g_log_mutex;

std::atomic<size_t> common_length = 1;

void log_level_map(const epee::LogLevel level, const std::string cat, const std::string_view x) {
  const std::filesystem::path p = cat;
  const std::string base_name = std::string(p.stem());

  const size_t base_name_length = base_name.size();

  if (base_name_length > common_length) {
    common_length = base_name_length;
  }

  const size_t leading_spaces_length = (common_length - base_name_length) / 2;
  const size_t trailing_spaces_length = common_length - base_name_length - leading_spaces_length;
  const std::string leading_spaces(leading_spaces_length, ' ');
  const std::string trailing_spaces(trailing_spaces_length, ' ');
  const std::string centered_cat =
    "[" + leading_spaces + base_name + trailing_spaces + "] ";

  const std::string cat_str = m_log_level == 0 ? "" : centered_cat;

  std::string log_header;
  switch (level) {
  case epee::LogLevel::Global:
    log_header = "I";
    break;
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

  auto now = std::chrono::system_clock::now();
  auto in_time_t = std::chrono::system_clock::to_time_t(now);

  std::lock_guard<std::mutex> guard(g_log_mutex);
  constexpr bool log_time = false;
  if (log_time) {
    std::cout << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%d %X")
              << " " << log_header << " " << cat_str << x << std::endl;
  } else {
    std::cout << log_header << " " << cat_str << x << std::endl;
  }
}

void log_level(const epee::LogLevel level, const std::string cat, const std::string_view x) {
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
    case epee::LogLevel::Global:
      log_level_map(level, cat, x);
      break;
    default:
      if (default_cat.find(cat) == default_cat.end()) return;
      log_level_map(level, cat, x);
      break;
    }
    break;
  default:
    break;
  }
}

} // epee
