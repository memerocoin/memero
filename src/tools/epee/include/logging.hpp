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


#pragma once

#include <sstream>
#include <iostream>
#include <memory>
#include <mutex>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "default"

namespace el {

enum class Level : unsigned int {
  Global,
  Fatal,
  Error,
  Warning,
  Info,
  Verbose,
  Debug,
  Trace,
  Unknown,
};
} // namespace el


namespace epee
{

void mlog_set_log_level(int level);
void mlog_set_log(const std::string x);
void log_level(const el::Level level, const std::string cat, const std::string_view x);

enum console_colors
{
  console_color_default,
  console_color_white,
  console_color_red,
  console_color_green,
  console_color_blue,
  console_color_cyan,
  console_color_magenta,
  console_color_yellow
};

bool is_stdout_a_tty();
void set_console_color(int color, bool bright);
void reset_console_color();

#define TRY_ENTRY()   try {
#define CATCH_ENTRY(location, return_val) }                             \
  catch(const std::exception& ex)                                       \
    {                                                                   \
      (void)(ex);                                                       \
      LOG_ERROR("Exception at [" << location << "], what=" << ex.what()); \
      return return_val;                                                \
    }                                                                   \
  catch(...)                                                            \
    {                                                                   \
      LOG_ERROR("Exception at [" << location << "], generic exception \"...\""); \
      return return_val;                                                \
    }

#define CATCH_ENTRY_L0(lacation, return_val) CATCH_ENTRY(lacation, return_val)

#define LOG_ERROR_AND_THROW(message)            \
  do {                                          \
    LOG_ERROR(message);                         \
    std::stringstream ss;                       \
    ss << message;                              \
    throw std::runtime_error(ss.str());         \
  } while(0)

#define LOG_ERROR_AND_THROW_IF(expr, message)   \
  do {                                          \
    if(expr)                                    \
      LOG_ERROR_AND_THROW(message);             \
  } while(0)

#define LOG_ERROR_AND_THROW_UNLESS(expr, message) \
  LOG_ERROR_AND_THROW_IF(!(expr), message)

#define RETURN_IF(expr, fail_ret_val)           \
  do {                                          \
    if(expr) {                                  \
      return fail_ret_val;                      \
    };                                          \
  } while(0)

#define RETURN_UNLESS(expr, fail_ret_val)       \
  RETURN_IF(!(expr), fail_ret_val)

#define LOG_ERROR_AND_RETURN_IF(expr, fail_ret_val, message)  \
  do {                                                        \
    if(expr) {                                                \
      LOG_ERROR(message);                                     \
      return fail_ret_val;                                    \
    };                                                        \
  } while(0)

#define LOG_ERROR_AND_RETURN_UNLESS(expr, fail_ret_val, message)  \
  LOG_ERROR_AND_RETURN_IF(!(expr), fail_ret_val, message)

#define LOG_WITH_LEVEL_AND_RETURN_IF(expr, fail_ret_val, l, message)  \
  do {                                                                \
    if(expr) {                                                        \
      LOG_PRINT_L##l(message);                                        \
      return fail_ret_val;                                            \
    };                                                                \
  } while(0)

#define LOG_WITH_LEVEL_AND_RETURN_UNLESS(expr, fail_ret_val, l, message) \
  LOG_WITH_LEVEL_AND_RETURN_IF(!(expr), fail_ret_val, l, message)

#define LOG_WITH_LEVEL_0_AND_RETURN_IF(expr, fail_ret_val, message) \
  LOG_WITH_LEVEL_AND_RETURN_IF(expr, fail_ret_val, 0, message)

#define LOG_WITH_LEVEL_0_AND_RETURN_UNLESS(expr, fail_ret_val, message) \
  LOG_WITH_LEVEL_0_AND_RETURN_IF(!(expr), fail_ret_val, message)

#define LOG_WITH_LEVEL_1_AND_RETURN_IF(expr, fail_ret_val, message) \
  LOG_WITH_LEVEL_AND_RETURN_IF(expr, fail_ret_val, 1, message)

#define LOG_WITH_LEVEL_1_AND_RETURN_UNLESS(expr, fail_ret_val, message) \
  LOG_WITH_LEVEL_1_AND_RETURN_IF(!(expr), fail_ret_val, message)

#define LOG_WITH_LEVEL_2_AND_RETURN_IF(expr, fail_ret_val, message) \
  LOG_WITH_LEVEL_AND_RETURN_IF(expr, fail_ret_val, 2, message)

#define LOG_WITH_LEVEL_2_AND_RETURN_UNLESS(expr, fail_ret_val, message) \
  LOG_WITH_LEVEL_2_AND_RETURN_IF(!(expr), fail_ret_val, message)


#define LOG_ERROR_IF(expr, message)             \
  do {                                          \
    if(expr) {                                  \
      LOG_ERROR(message);                       \
      return;                                   \
    };                                          \
  } while(0)

#define LOG_ERROR_UNLESS(expr, message)         \
  LOG_ERROR_IF(!(expr), message)

#define LOG_WARNING_AND_THROW_IF(expr, message) \
  do {                                          \
    if(expr) {                                  \
      LOG_WARNING(message);                     \
      throw std::runtime_error(message);        \
    };                                          \
  } while(0)

#define LOG_WARNING_AND_THROW_UNLESS(expr, message) \
  LOG_WARNING_AND_THROW_IF(!(expr), message)

} // epee

#define LOG_CATEGORY(level, cat, color, x) do {                   \
    std::ostringstream stream;                                    \
    stream << x;                                                  \
    epee::log_level(level, cat, std::string_view(stream.str()));  \
  } while (0)

#define LOG_CATEGORY_FATAL(cat,x) LOG_CATEGORY(el::Level::Fatal,cat, el::Color::Default, x)
#define LOG_CATEGORY_ERROR(cat,x) LOG_CATEGORY(el::Level::Error,cat, el::Color::Default, x)
#define LOG_CATEGORY_WARNING(cat,x) LOG_CATEGORY(el::Level::Warning,cat, el::Color::Default, x)
#define LOG_CATEGORY_INFO(cat,x) LOG_CATEGORY(el::Level::Info,cat, el::Color::Default, x)
#define LOG_CATEGORY_VERBOSE(cat,x) LOG_CATEGORY(el::Level::Verbose,cat, el::Color::Default, x)
#define LOG_CATEGORY_DEBUG(cat,x) LOG_CATEGORY(el::Level::Debug,cat, el::Color::Default, x)
#define LOG_CATEGORY_TRACE(cat,x) LOG_CATEGORY(el::Level::Trace,cat, el::Color::Default, x)

#define LOG_CATEGORY_COLOR(level,cat,color,x) LOG_CATEGORY(level,cat,color,x)
#define LOG_CATEGORY_RED(level,cat,x) LOG_CATEGORY_COLOR(level,cat,el::Color::Red,x)
#define LOG_CATEGORY_GREEN(level,cat,x) LOG_CATEGORY_COLOR(level,cat,el::Color::Green,x)
#define LOG_CATEGORY_YELLOW(level,cat,x) LOG_CATEGORY_COLOR(level,cat,el::Color::Yellow,x)
#define LOG_CATEGORY_BLUE(level,cat,x) LOG_CATEGORY_COLOR(level,cat,el::Color::Blue,x)
#define LOG_CATEGORY_MAGENTA(level,cat,x) LOG_CATEGORY_COLOR(level,cat,el::Color::Magenta,x)
#define LOG_CATEGORY_CYAN(level,cat,x) LOG_CATEGORY_COLOR(level,cat,el::Color::Cyan,x)

#define LOG_RED(level,x) LOG_CATEGORY_RED(level,MONERO_DEFAULT_LOG_CATEGORY,x)
#define LOG_GREEN(level,x) LOG_CATEGORY_GREEN(level,MONERO_DEFAULT_LOG_CATEGORY,x)
#define LOG_YELLOW(level,x) LOG_CATEGORY_YELLOW(level,MONERO_DEFAULT_LOG_CATEGORY,x)
#define LOG_BLUE(level,x) LOG_CATEGORY_BLUE(level,MONERO_DEFAULT_LOG_CATEGORY,x)
#define LOG_MAGENTA(level,x) LOG_CATEGORY_MAGENTA(level,MONERO_DEFAULT_LOG_CATEGORY,x)
#define LOG_CYAN(level,x) LOG_CATEGORY_CYAN(level,MONERO_DEFAULT_LOG_CATEGORY,x)

#define LOG_FATAL(x) LOG_CATEGORY_FATAL(MONERO_DEFAULT_LOG_CATEGORY,x)
#define LOG_ERROR(x) LOG_CATEGORY_ERROR(MONERO_DEFAULT_LOG_CATEGORY,x)
#define LOG_WARNING(x) LOG_CATEGORY_WARNING(MONERO_DEFAULT_LOG_CATEGORY,x)
#define LOG_INFO(x) LOG_CATEGORY_INFO(MONERO_DEFAULT_LOG_CATEGORY,x)
#define LOG_VERBOSE(x) LOG_CATEGORY_VERBOSE(MONERO_DEFAULT_LOG_CATEGORY,x)
#define LOG_DEBUG(x) LOG_CATEGORY_DEBUG(MONERO_DEFAULT_LOG_CATEGORY,x)
#define LOG_TRACE(x) LOG_CATEGORY_TRACE(MONERO_DEFAULT_LOG_CATEGORY,x)

#define LOG_GLOBAL_INFO(x) LOG_CATEGORY_INFO("global",x)
#define LOG_GLOBAL_INFO_RED(x) LOG_CATEGORY_RED(el::Level::Info, "global",x)
#define LOG_GLOBAL_INFO_GREEN(x) LOG_CATEGORY_GREEN(el::Level::Info, "global",x)
#define LOG_GLOBAL_INFO_YELLOW(x) LOG_CATEGORY_YELLOW(el::Level::Info, "global",x)
#define LOG_GLOBAL_INFO_BLUE(x) LOG_CATEGORY_BLUE(el::Level::Info, "global",x)
#define LOG_GLOBAL_INFO_MAGENTA(x) LOG_CATEGORY_MAGENTA(el::Level::Info, "global",x)
#define LOG_GLOBAL_INFO_CYAN(x) LOG_CATEGORY_CYAN(el::Level::Info, "global",x)

#define LOG_GLOBAL_VERBOSE(x) LOG_CATEGORY_VERBOSE("global",x)

#define LOG_PRINT_L0(x) LOG_WARNING(x)
#define LOG_PRINT_L1(x) LOG_INFO(x)
#define LOG_PRINT_L2(x) LOG_VERBOSE(x)
#define LOG_PRINT_L3(x) LOG_DEBUG(x)
#define LOG_PRINT_L4(x) LOG_TRACE(x)

#define _dbg3(x) LOG_TRACE(x)
#define _dbg2(x) LOG_DEBUG(x)
#define _dbg1(x) LOG_DEBUG(x)
#define _info(x) LOG_INFO(x)
#define _note(x) LOG_VERBOSE(x)
#define _fact(x) LOG_DEBUG(x)
#define _mark(x) LOG_DEBUG(x)
#define _warn(x) LOG_WARNING(x)
#define _erro(x) LOG_ERROR(x)

#define LOG_SET_THREAD_NAME(x)
