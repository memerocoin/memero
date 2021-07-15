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

// #include "spdlog/spdlog.h"
// #include "spdlog/sinks/stdout_color_sinks.h"

#include <filesystem>
#include <set>
#include <atomic>

#include <boost/algorithm/string.hpp>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "logging"

#define MLOG_BASE_FORMAT "%datetime{%Y-%M-%d %H:%m:%s.%g}\t%thread\t%level\t%logger\t%loc\t%msg"

// #define MLOG_LOG(x) CINFO(el::base::Writer,el::base::DispatchAction::FileOnlyLog,MONERO_DEFAULT_LOG_CATEGORY) << x

using namespace epee;

std::string mlog_get_default_log_path(const char *default_filename)
{
  return (std::filesystem::path(config::def::log_path)).string();
}

static const char *get_default_categories(int level)
{
  const char *categories = "";
  switch (level)
  {
    case 0:
      categories = "*:WARNING,net:FATAL,net.http:FATAL,net.ssl:FATAL,net.p2p:FATAL,net.cn:FATAL,daemon.rpc:FATAL,global:INFO,verify:FATAL,serialization:FATAL,daemon.rpc.payment:ERROR,stacktrace:INFO,logging:INFO,msgwriter:INFO";
      break;
    case 1:
      categories = "*:INFO,global:INFO,stacktrace:INFO,logging:INFO,msgwriter:INFO,perf.*:DEBUG";
      break;
    case 2:
      categories = "*:DEBUG";
      break;
    case 3:
      categories = "*:TRACE,*.dump:DEBUG";
      break;
    case 4:
      categories = "*:TRACE";
      break;
    default:
      break;
  }
  return categories;
}

void mlog_configure(const std::string &filename_base, bool console)
{
  const char *monero_log = getenv("MONERO_LOGS");
  if (!monero_log)
  {
    monero_log = get_default_categories(0);
  }
  mlog_set_log(monero_log);
}

void mlog_set_categories(const char *categories)
{
  std::string new_categories;
  if (*categories)
  {
    if (*categories == '+')
    {
      ++categories;
      new_categories = mlog_get_categories();
      if (*categories)
      {
        if (!new_categories.empty())
          new_categories += ",";
        new_categories += categories;
      }
    }
    else if (*categories == '-')
    {
      ++categories;
      new_categories = mlog_get_categories();
      std::vector<std::string> single_categories;
      boost::split(single_categories, categories, boost::is_any_of(","), boost::token_compress_on);
      for (const std::string &s: single_categories)
      {
        size_t pos = new_categories.find(s);
        if (pos != std::string::npos)
          new_categories = new_categories.erase(pos, s.size());
      }
    }
    else
    {
      new_categories = categories;
    }
  }
  // el::Loggers::setCategories(new_categories.c_str(), true);
  // MLOG_LOG("New log categories: " << el::Loggers::getCategories());
}

std::string mlog_get_categories()
{
  // return el::Loggers::getCategories();
  return "";
}

std::atomic<int> m_log_level = 0;

// maps epee style log level to new logging system
void mlog_set_log_level(int level)
{
  const char *categories = get_default_categories(level);
  mlog_set_categories(categories);
  m_log_level = level;
}

void mlog_set_log(const char *log)
{
  long level;
  char *ptr = NULL;

  if (!*log)
  {
    mlog_set_categories(log);
    return;
  }
  level = strtol(log, &ptr, 10);
  if (ptr && *ptr)
  {
    // we can have a default level, eg, 2,foo:ERROR
    if (*ptr == ',') {
      std::string new_categories = std::string(get_default_categories(level)) + ptr;
      mlog_set_categories(new_categories.c_str());
    }
    else {
      mlog_set_categories(log);
    }
  }
  else if (level >= 0 && level <= 4)
  {
    mlog_set_log_level(level);
  }
  else
  {
    MERROR("Invalid numerical log level: " << log);
  }
}

namespace epee
{

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

}

// SPDLOG_LEVEL_TRACE,
// SPDLOG_LEVEL_DEBUG,
// SPDLOG_LEVEL_INFO,
// SPDLOG_LEVEL_WARN,
// SPDLOG_LEVEL_ERROR,
// SPDLOG_LEVEL_CRITICAL,
// SPDLOG_LEVEL_OFF

const std::set<std::string> default_cat = {"global", "logging"};
std::mutex g_log_mutex;

void log_level_map(const el::Level level, const std::string cat, const std::string_view x) {
  // auto _spd_log_handle = spdlog::get(cat);

  // if (!_spd_log_handle) {
  //   _spd_log_handle = spdlog::stdout_color_mt(cat);
  //   std::string format_str;
  //   if (default_cat.find(cat) != default_cat.end()) {
  //     format_str = "%Y-%m-%d %T.%e %L %v";
  //   } else {
  //     format_str = "%Y-%m-%d %T.%e %L [%n] %v";
  //   }
  //   _spd_log_handle->set_pattern(format_str, spdlog::pattern_time_type::utc);
  // }


  const std::string cat_str = default_cat.find(cat) != default_cat.end() ? "" : "[" + cat + "] ";

  std::string log_header;
  switch (level) {
  case el::Level::Trace:
    // _spd_log_handle->trace(x);
    log_header = "T";
    break;
  case el::Level::Debug:
    // _spd_log_handle->debug(x);
    log_header = "D";
    break;
  case el::Level::Info:
    // _spd_log_handle->info(x);
    log_header = "I";
    break;
  case el::Level::Warning:
    // _spd_log_handle->warn(x);
    log_header = "W";
    break;
  case el::Level::Error:
    // _spd_log_handle->error(x);
    log_header = "E";
    break;
  case el::Level::Fatal:
    // _spd_log_handle->critical(x);
    log_header = "F";
    break;
  default:
    // _spd_log_handle->off(x);
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
