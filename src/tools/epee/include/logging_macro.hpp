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

#define LOG_DEBUG_MUTE(x)
#define LOG_VERBOSE_MUTE(x)
#define LOG_WARNING_MUTE(x)
#define LOG_ERROR_MUTE(x)

#define TRY_ENTRY()   try {

#define CATCH_ENTRY(location, return_val) }     \
    catch(const std::exception& ex)             \
      {                                         \
        (void)(ex);                             \
        LOG_ERROR                               \
          (                                     \
           "Exception at ["                     \
           + std::string(location)              \
           + "], what="                         \
           + std::string(ex.what())) ;          \
        return return_val;                      \
      }                                         \
    catch(...)                                  \
      {                                         \
        LOG_ERROR                               \
          (                                     \
           "Exception at ["                     \
           + std::string(location)              \
           + "], generic exception \"...\"") ;  \
        return return_val;                      \
      }

#define CATCH_ENTRY_L0(lacation, return_val)    \
  CATCH_ENTRY(lacation, return_val)
