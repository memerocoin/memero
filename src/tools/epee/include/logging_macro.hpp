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

#define LOG_AND_RETURN_IF(level, expr, fail_ret_val, x) \
  do {                                                  \
    if(expr) {                                          \
      LOG_CATEGORY                                      \
        (                                               \
         level                                          \
         , DEFAULT_LOG_CATEGORY                         \
         , x );                                         \
      return fail_ret_val;                              \
    };                                                  \
  } while(0)

#define LOG_AND_RETURN_UNLESS(level, expr, fail_ret_val, x) \
  LOG_AND_RETURN_IF(level, !(expr), fail_ret_val, x)

#define LOG_ERROR_AND_RETURN_IF(expr, fail_ret_val, x)            \
  LOG_AND_RETURN_IF(epee::LogLevel::Error, expr, fail_ret_val, x)

#define LOG_ERROR_AND_RETURN_UNLESS(expr, fail_ret_val, x)            \
  LOG_AND_RETURN_UNLESS(epee::LogLevel::Error, expr, fail_ret_val, x)


#define LOG_CATEGORY_COLOR(level, cat, color, x) do { \
    std::ostringstream stream;                        \
    stream << x;                                      \
    const auto s = stream.str();                      \
    epee::log_level_cat_color(level, cat, s, color);  \
  } while (0)

#define LOG_CATEGORY(level, cat, x) do {        \
    LOG_CATEGORY_COLOR                          \
      (                                         \
       level                                    \
       , cat                                    \
       , epee::console_colors::color_default    \
       , x );                                   \
  } while (0)

#define LOG_COLOR(color, level, x) do {         \
    LOG_CATEGORY_COLOR                          \
      (                                         \
       level                                    \
       , DEFAULT_LOG_CATEGORY                   \
       , color                                  \
       , x );                                   \
  } while (0)

#define LOG_DEFAULT(level, x)                   \
  LOG_CATEGORY(level, DEFAULT_LOG_CATEGORY, x)

#define LOG_GLOBAL(x)                                           \
  LOG_CATEGORY(epee::LogLevel::Info, epee::GLOBAL_CATEGORY, x)

#define LOG_FATAL(x) LOG_DEFAULT(epee::LogLevel::Fatal, x)
#define LOG_ERROR(x) LOG_DEFAULT(epee::LogLevel::Error, x)
#define LOG_WARNING(x) LOG_DEFAULT(epee::LogLevel::Warning, x)
#define LOG_INFO(x) LOG_DEFAULT(epee::LogLevel::Info, x)
#define LOG_VERBOSE(x) LOG_DEFAULT(epee::LogLevel::Verbose, x)
#define LOG_DEBUG(x) LOG_DEFAULT(epee::LogLevel::Debug, x)
#define LOG_TRACE(x) LOG_DEFAULT(epee::LogLevel::Trace, x)

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


#define TRY_ENTRY()   try {
#define CATCH_ENTRY(location, return_val) }                         \
  catch(const std::exception& ex)                                   \
    {                                                               \
      (void)(ex);                                                   \
      LOG_ERROR                                                     \
        ("Exception at [" << location << "], what=" << ex.what());  \
      return return_val;                                            \
    }                                                               \
  catch(...)                                                        \
    {                                                               \
      LOG_ERROR                                                     \
        (                                                           \
         "Exception at ["                                           \
         << location <<                                             \
         "], generic exception \"...\"");                           \
      return return_val;                                            \
    }

#define CATCH_ENTRY_L0(lacation, return_val)    \
  CATCH_ENTRY(lacation, return_val)
