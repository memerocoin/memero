// Copyright (c) 2006-2013, Andrey N. Sabelnikov, www.sabelnikov.net
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// * Neither the name of the Andrey N. Sabelnikov nor the
// names of its contributors may be used to endorse or promote products
// derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER  BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//


#include "tools/epee/include/misc_log_ex.h"

#include "config/lol.hpp"

#include <filesystem>
#include <set>
#include <atomic>

#include <boost/algorithm/string.hpp>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "logging"

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
    MERROR("Invalid numerical log level: " << x);
  }
}

bool is_stdout_a_tty()
{
  static std::atomic<bool> initialized(false);
  static std::atomic<bool> is_a_tty(false);

  if (!initialized.load(std::memory_order_acquire))
  {
    is_a_tty.store(0 != isatty(fileno(stdout)), std::memory_order_relaxed);
    initialized.store(true, std::memory_order_release);
  }

  return is_a_tty.load(std::memory_order_relaxed);
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

const std::set<std::string> default_cat = {"global", "logging"};
std::mutex g_log_mutex;

void log_level_map(const el::Level level, const std::string cat, const std::string_view x) {
  const std::string cat_str = default_cat.find(cat) != default_cat.end() ? "" : "[" + cat + "] ";

  std::string log_header;
  switch (level) {
  case el::Level::Trace:
    log_header = "T";
    break;
  case el::Level::Debug:
    log_header = "D";
    break;
  case el::Level::Info:
    log_header = "I";
    break;
  case el::Level::Warning:
    log_header = "W";
    break;
  case el::Level::Error:
    log_header = "E";
    break;
  case el::Level::Fatal:
    log_header = "F";
    break;
  default:
    break;
  }

  auto now = std::chrono::system_clock::now();
  auto in_time_t = std::chrono::system_clock::to_time_t(now);

  std::lock_guard<std::mutex> guard(g_log_mutex);
  std::cout << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%d %X")
            << " " << log_header << " " << cat_str << x << std::endl;
}

void log_level(const el::Level level, const std::string cat, const std::string_view x) {
  if (level == el::Level::Fatal) {
    log_level_map(level, cat, x);
    return;
  }

  switch (m_log_level) {
  case 4:
    log_level_map(level, cat, x);
    return;
  case 3:
    switch(level) {
    case el::Level::Trace:
      break;
    default:
      log_level_map(level, cat, x);
      break;
    }
  case 2:
    switch(level) {
    case el::Level::Trace:
    case el::Level::Debug:
      break;
    default:
      log_level_map(level, cat, x);
      break;
    }
  case 1:
    switch(level) {
    case el::Level::Trace:
    case el::Level::Debug:
    case el::Level::Error:
      break;
    default:
      log_level_map(level, cat, x);
      break;
    }
  case 0:
    switch(level) {
    case el::Level::Trace:
    case el::Level::Debug:
    case el::Level::Error:
      break;
    case el::Level::Info:
    case el::Level::Warning:
      if (default_cat.find(cat) == default_cat.end()) return;
      log_level_map(level, cat, x);
      break;
    default:
      log_level_map(level, cat, x);
      break;
    }
  default:
    break;
  }
}

} // epee
