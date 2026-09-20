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


Parts of this file are originally 
copyright (c) 2012-2013 The Cryptonote developers

*/

#include "daemon_common.hpp"

#include "config/version/version.hpp"
#include <iostream>

namespace daemon_common {

  std::string get_version_string() {
    return "Memero '"
      + std::string(MEMERO_RELEASE_NAME)
      + "' (v"
      + std::string(MEMERO_VERSION_FULL)
      + ")";
  }

  void show_version() {
    std::cout
      << get_version_string()
      << std::endl;
  }

}
