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


#pragma once

#include <sstream>
#include <iostream>
#include <memory>
#include <mutex>

#undef DEFAULT_CAT
#ifdef __FILE_NAME__
#define DEFAULT_CAT __FILE_NAME__

#else
#define DEFAULT_CAT __FILE__
#endif

namespace epee
{
  constexpr std::string_view GLOBAL_CATEGORY = "global";

  enum LogLevel
    {
    Fatal,
    Error,
    Warning,
    Info,
    Verbose,
    Debug,
    Trace,
  };

  void set_log_level(const int level);
  void set_log_level_from_string(const std::string x);
  void log_level_cat
  (
   const epee::LogLevel level
   , const std::string_view cat
   , const std::string_view x
   );

  enum console_colors
    {
      color_default,
      white,
      red,
      green,
      blue,
      cyan,
      magenta,
      yellow
    };

  bool is_stdout_a_tty();
  void set_console_color
  (
   const epee::console_colors color
   , const bool bright
   );
  void reset_console_color();

  void log_level_cat_color
  (
   const epee::LogLevel level
   , const std::string_view cat
   , const std::string_view x
   , const epee::console_colors color
   );

} // epee

void log_error_and_throw
(
 const std::string_view cat
 , const std::string_view x
 );

void log_error_and_throw_if
(
 const bool expr
 , const std::string_view cat
 , const std::string_view x
 );

void log_error_and_throw_unless
(
 const bool expr
 , const std::string_view cat
 , const std::string_view x
 );


void log_trace
(
 const std::string_view cat
 , const std::string_view x
 );

void log_debug
(
 const std::string_view cat
 , const std::string_view x
 );

void log_verbose
(
 const std::string_view cat
 , const std::string_view x
 );

void log_fatal
(
 const std::string_view cat
 , const std::string_view x
 );

void log_info
(
 const std::string_view cat
 , const std::string_view x
 );

void log_error
(
 const std::string_view cat
 , const std::string_view x
 );

void log_warning
(
 const std::string_view cat
 , const std::string_view x
 );

void LOG_GLOBAL(const std::string_view x);

void LOG_CATEGORY
(
 const epee::LogLevel level
 , const std::string_view cat
 , const std::string_view x
 );

void LOG_CATEGORY_COLOR
(
 const epee::LogLevel level
 , const std::string_view cat
 , const epee::console_colors color
 , const std::string_view x
 );


#define LOG_COLOR(color, level, x)                          \
  do { LOG_CATEGORY_COLOR(level, DEFAULT_CAT, color, x); }  \
  while (0)

#define LOG_ERROR_AND_THROW(x)                          \
  do { log_error_and_throw(DEFAULT_CAT, x); } while (0)

#define LOG_ERROR_AND_THROW_IF(expr, x)                           \
  do { log_error_and_throw_if(expr, DEFAULT_CAT, x); } while (0)

#define LOG_ERROR_AND_THROW_UNLESS(expr, x)                 \
  do { log_error_and_throw_unless(expr, DEFAULT_CAT, x); }  \
  while (0)

#define LOG_WARNING(x) do { log_warning(DEFAULT_CAT, x); } while(0)
#define LOG_FATAL(x) do { log_fatal(DEFAULT_CAT, x); } while(0)
#define LOG_ERROR(x) do { log_error(DEFAULT_CAT, x); } while(0)
#define LOG_INFO(x) do { log_info(DEFAULT_CAT, x); } while(0)
#define LOG_VERBOSE(x) do { log_verbose(DEFAULT_CAT, x); } while(0)
#define LOG_DEBUG(x) do { log_debug(DEFAULT_CAT, x); } while(0)
#define LOG_TRACE(x) do { log_trace(DEFAULT_CAT, x); } while(0)

#define LOG_DEBUG_MUTE(x)

#define _note LOG_VERBOSE
#define _erro LOG_ERROR
#define _info LOG_INFO
#define _fact LOG_DEBUG
#define _dbg1 LOG_DEBUG
#define _dbg2 LOG_DEBUG
#define _dbg3 LOG_TRACE

#define LOG_PRINT_L0 LOG_WARNING
#define LOG_PRINT_L1 LOG_INFO
#define LOG_PRINT_L2 LOG_VERBOSE
#define LOG_PRINT_L3 LOG_DEBUG


