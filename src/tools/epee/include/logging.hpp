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

#undef DEFAULT_LOG_CATEGORY

#ifdef __FILE_NAME__
#define DEFAULT_LOG_CATEGORY __FILE_NAME__

#else
#define DEFAULT_LOG_CATEGORY __FILE__
#endif

namespace epee
{
  constexpr std::string_view GLOBAL_CATEGORY = "global";

  enum class LogLevel : unsigned int {
    Fatal,
    Error,
    Warning,
    Info,
    Verbose,
    Debug,
    Trace,
    Unknown,
  };

  void mlog_set_log_level(int level);
  void mlog_set_log(const std::string x);
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
  void set_console_color(int color, bool bright);
  void reset_console_color();

  void log_level_cat_color
  (
   const epee::LogLevel level
   , const std::string_view cat
   , const std::string_view x
   , const epee::console_colors color
   );

} // epee

void LOG_ERROR_AND_THROW(const std::string_view x);

void LOG_ERROR_AND_THROW_IF
(
 const bool expr
 , const std::string_view x
 );

void LOG_ERROR_AND_THROW_UNLESS
(
 const bool expr
 , const std::string_view x
 );


void LOG_DEFAULT
(
 const epee::LogLevel level
 , const std::string_view x
 );

void LOG_TRACE(const std::string_view x);
void LOG_DEBUG(const std::string_view x);
void LOG_VERBOSE(const std::string_view x);
void LOG_FATAL(const std::string_view x);
void LOG_WARNING(const std::string_view x);
void LOG_INFO(const std::string_view x);
void LOG_ERROR(const std::string_view x);
void LOG_GLOBAL(const std::string_view x);

void LOG_COLOR
(
 const epee::console_colors color
 , const epee::LogLevel level
 , const std::string_view x
 );

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

constexpr auto _dbg3 = LOG_TRACE;

constexpr auto _note = LOG_VERBOSE;
constexpr auto _erro = LOG_ERROR;
constexpr auto _info = LOG_INFO;
constexpr auto _fact = LOG_DEBUG;
constexpr auto _dbg1 = LOG_DEBUG;
constexpr auto _dbg2 = LOG_DEBUG;

constexpr auto LOG_PRINT_L0 = LOG_WARNING;
constexpr auto LOG_PRINT_L1 = LOG_INFO;
constexpr auto LOG_PRINT_L2 = LOG_VERBOSE;
constexpr auto LOG_PRINT_L3 = LOG_DEBUG;

#define LOG_DEBUG_MUTE(x)
