//
//  Bismillah ar-Rahmaan ar-Raheem
//
//  Easylogging++ v9.96.7
//  Single-header only, cross-platform logging library for C++ applications
//
//  Copyright (c) 2012-2018 Zuhd Web Services
//  Copyright (c) 2012-2018 @abumusamq
//
//  This library is released under the MIT Licence.
//  https://github.com/zuhd-org/easyloggingpp/blob/master/LICENSE
//
//  https://zuhd.org
//  http://muflihun.com
//

#pragma once

namespace el {
/// @brief Namespace containing base/internal functionality used by Easylogging++
namespace base {
/// @brief Data types used by Easylogging++
namespace type {
typedef unsigned int EnumType;
}  // namespace type
} // namespace base

enum class Level : base::type::EnumType {
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
enum class Color : base::type::EnumType {
  Default,
  Red,
  Green,
  Yellow,
  Blue,
  Magenta,
  Cyan,
};
} // namespace el
