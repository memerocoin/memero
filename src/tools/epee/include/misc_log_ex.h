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

typedef unsigned int EnumType;

enum class Level : EnumType {
  /// @brief Generic level that represents all the levels. Useful when setting global configuration for all levels
  Global = 1,
  /// @brief Information that can be useful to back-trace certain events - mostly useful than debug logs.
  Trace = 2,
  /// @brief Informational events most useful for developers to debug application
  Debug = 4,
  /// @brief Severe error information that will presumably abort application
  Fatal = 8,
  /// @brief Information representing errors in application but application will keep running
  Error = 16,
  /// @brief Useful when application has potentially harmful situtaions
  Warning = 32,
  /// @brief Information that can be highly useful and vary with verbose logging level.
  Verbose = 64,
  /// @brief Mainly useful to represent current progress of application
  Info = 128,
  /// @brief Represents unknown level
  Unknown = 1010
};
} // namespace el


#define MCLOG_TYPE(level, cat, color, type, x) do { \
    std::ostringstream stream;                                          \
    stream << x;                                                        \
    epee::log_level(level, cat, std::string_view(stream.str()));        \
  } while (0)

#define MCLOG(level, cat, color, x) MCLOG_TYPE(level, cat, color, el::base::DispatchAction::NormalLog, x)
#define MCLOG_FILE(level, cat, x) MCLOG_TYPE(level, cat, el::Color::Default, el::base::DispatchAction::FileOnlyLog, x)

#define MCFATAL(cat,x) MCLOG(el::Level::Fatal,cat, el::Color::Default, x)
#define MCERROR(cat,x) MCLOG(el::Level::Error,cat, el::Color::Default, x)
#define MCWARNING(cat,x) MCLOG(el::Level::Warning,cat, el::Color::Default, x)
#define MCINFO(cat,x) MCLOG(el::Level::Info,cat, el::Color::Default, x)
#define MCDEBUG(cat,x) MCLOG(el::Level::Debug,cat, el::Color::Default, x)
#define MCTRACE(cat,x) MCLOG(el::Level::Trace,cat, el::Color::Default, x)

#define MCLOG_COLOR(level,cat,color,x) MCLOG(level,cat,color,x)
#define MCLOG_RED(level,cat,x) MCLOG_COLOR(level,cat,el::Color::Red,x)
#define MCLOG_GREEN(level,cat,x) MCLOG_COLOR(level,cat,el::Color::Green,x)
#define MCLOG_YELLOW(level,cat,x) MCLOG_COLOR(level,cat,el::Color::Yellow,x)
#define MCLOG_BLUE(level,cat,x) MCLOG_COLOR(level,cat,el::Color::Blue,x)
#define MCLOG_MAGENTA(level,cat,x) MCLOG_COLOR(level,cat,el::Color::Magenta,x)
#define MCLOG_CYAN(level,cat,x) MCLOG_COLOR(level,cat,el::Color::Cyan,x)

#define MLOG_RED(level,x) MCLOG_RED(level,MONERO_DEFAULT_LOG_CATEGORY,x)
#define MLOG_GREEN(level,x) MCLOG_GREEN(level,MONERO_DEFAULT_LOG_CATEGORY,x)
#define MLOG_YELLOW(level,x) MCLOG_YELLOW(level,MONERO_DEFAULT_LOG_CATEGORY,x)
#define MLOG_BLUE(level,x) MCLOG_BLUE(level,MONERO_DEFAULT_LOG_CATEGORY,x)
#define MLOG_MAGENTA(level,x) MCLOG_MAGENTA(level,MONERO_DEFAULT_LOG_CATEGORY,x)
#define MLOG_CYAN(level,x) MCLOG_CYAN(level,MONERO_DEFAULT_LOG_CATEGORY,x)

#define MFATAL(x) MCFATAL(MONERO_DEFAULT_LOG_CATEGORY,x)
#define MERROR(x) MCERROR(MONERO_DEFAULT_LOG_CATEGORY,x)
#define MWARNING(x) MCWARNING(MONERO_DEFAULT_LOG_CATEGORY,x)
#define MINFO(x) MCINFO(MONERO_DEFAULT_LOG_CATEGORY,x)
#define MDEBUG(x) MCDEBUG(MONERO_DEFAULT_LOG_CATEGORY,x)
#define MTRACE(x) MCTRACE(MONERO_DEFAULT_LOG_CATEGORY,x)
#define MLOG(level,x) MCLOG(level,MONERO_DEFAULT_LOG_CATEGORY,el::Color::Default,x)

#define MGINFO(x) MCINFO("global",x)
#define MGINFO_RED(x) MCLOG_RED(el::Level::Info, "global",x)
#define MGINFO_GREEN(x) MCLOG_GREEN(el::Level::Info, "global",x)
#define MGINFO_YELLOW(x) MCLOG_YELLOW(el::Level::Info, "global",x)
#define MGINFO_BLUE(x) MCLOG_BLUE(el::Level::Info, "global",x)
#define MGINFO_MAGENTA(x) MCLOG_MAGENTA(el::Level::Info, "global",x)
#define MGINFO_CYAN(x) MCLOG_CYAN(el::Level::Info, "global",x)



#define LOG_ERROR(x) MERROR(x)
#define LOG_PRINT_L0(x) MWARNING(x)
#define LOG_PRINT_L1(x) MINFO(x)
#define LOG_PRINT_L2(x) MDEBUG(x)
#define LOG_PRINT_L3(x) MTRACE(x)
#define LOG_PRINT_L4(x) MTRACE(x)

#define _dbg3(x) MTRACE(x)
#define _dbg2(x) MDEBUG(x)
#define _dbg1(x) MDEBUG(x)
#define _info(x) MINFO(x)
#define _note(x) MDEBUG(x)
#define _fact(x) MDEBUG(x)
#define _mark(x) MDEBUG(x)
#define _warn(x) MWARNING(x)
#define _erro(x) MERROR(x)

#define MLOG_SET_THREAD_NAME(x)

namespace epee
{

void mlog_set_log_level(int level);
void mlog_set_log(const std::string x);
void log_level(const el::Level level, const std::string cat, const std::string_view x);

#define ENDL std::endl

#define TRY_ENTRY()   try {
#define CATCH_ENTRY(location, return_val) } \
  catch(const std::exception& ex) \
{ \
  (void)(ex); \
  LOG_ERROR("Exception at [" << location << "], what=" << ex.what()); \
  return return_val; \
}\
  catch(...)\
{\
  LOG_ERROR("Exception at [" << location << "], generic exception \"...\"");\
  return return_val; \
}

#define CATCH_ENTRY_L0(lacation, return_val) CATCH_ENTRY(lacation, return_val)
#define CATCH_ENTRY_L1(lacation, return_val) CATCH_ENTRY(lacation, return_val)
#define CATCH_ENTRY_L2(lacation, return_val) CATCH_ENTRY(lacation, return_val)
#define CATCH_ENTRY_L3(lacation, return_val) CATCH_ENTRY(lacation, return_val)
#define CATCH_ENTRY_L4(lacation, return_val) CATCH_ENTRY(lacation, return_val)


#define LOG_AND_THROW(message) {LOG_ERROR(message); std::stringstream ss; ss << message; throw std::runtime_error(ss.str());}

#define ASSERT_OR_LOG_THROW(expr, message)      \
  do {                                          \
    if(!(expr))                                 \
      LOG_AND_THROW(message);                   \
  } while(0)


#ifndef ASSERT_OR_RETURN
#define ASSERT_OR_RETURN(expr, fail_ret_val)    \
  do {                                          \
    if(!(expr)) {                               \
      return fail_ret_val;                      \
    };                                          \
  } while(0)
#endif

#ifndef ASSERT_OR_LOG_RETURN
#define ASSERT_OR_LOG_RETURN(expr, fail_ret_val, message) \
  do {                                                    \
    if(!(expr)) {                                         \
      LOG_ERROR(message);                                 \
      return fail_ret_val;                                \
    };                                                    \
  } while(0)
#endif

#ifndef CHECK_OR_LOG_RETURN_LOGLEVEL
#define CHECK_OR_LOG_RETURN_LOGLEVEL(expr, fail_ret_val, l, message)  \
  do {                                                                \
    if(!(expr)) {                                                     \
      LOG_PRINT_L##l(message);                                        \
      return fail_ret_val;                                            \
    };                                                                \
  } while(0)
#endif

#ifndef CHECK_OR_LOG_RETURN
#define CHECK_OR_LOG_RETURN(expr, fail_ret_val, message) CHECK_OR_LOG_RETURN_LOGLEVEL(expr, fail_ret_val, 0, message)
#endif

#ifndef CHECK_OR_LOG_RETURN_LOGLEVEL_1
#define CHECK_OR_LOG_RETURN_LOGLEVEL_1(expr, fail_ret_val, message) CHECK_OR_LOG_RETURN_LOGLEVEL(expr, fail_ret_val, 1, message)
#endif


#ifndef ASSERT_OR_LOG
#define ASSERT_OR_LOG(expr, message)            \
  do {                                          \
    if(!(expr)) {                               \
      LOG_ERROR(message);                       \
      return;                                   \
    };                                          \
  } while(0)
#endif

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

}

