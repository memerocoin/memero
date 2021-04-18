# Copyright (c) 2021, The Lolnero Project
# Copyright (c) 2014-2020, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers




# cmake
cmake_minimum_required(VERSION 3.10.0)
project(lolnero)




# tools
list(INSERT CMAKE_MODULE_PATH 0
  "${CMAKE_CURRENT_SOURCE_DIR}/etc/cmake")




# language
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)




# build type
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()




# libs

## threads
find_package(Threads REQUIRED)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

## openssl
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

## boost
find_package(Boost 1.74 REQUIRED COMPONENTS system serialization program_options)
include_directories(${Boost_INCLUDE_DIRS})

## readline
option(USE_READLINE "Build with GNU readline support." ON)
if(USE_READLINE)
  find_package(Readline)
  if(READLINE_FOUND AND GNU_READLINE_FOUND)
    add_definitions(-DHAVE_READLINE)
    include_directories(${Readline_INCLUDE_DIR})
    message(STATUS "Found readline library at: ${Readline_ROOT_DIR}")
    set(EPEE_READLINE epee_readline)
  else()
    message(STATUS "Could not find GNU readline library so building without readline support")
  endif()
endif()

## sodium
find_library(SODIUM_LIBRARY sodium)

## rapidjson, only for android
include_directories(vendor/rapidjson/include)




# set global include path
include_directories(
  src
)




# let's go

## version
include(Version)
add_library(version ${CMAKE_BINARY_DIR}/version.cpp)
add_dependencies(version genversion)

## logging
add_definitions(-DAUTO_INITIALIZE_EASYLOGGINGPP)
add_library( easylogging
  src/tools/easylogging++/easylogging++.cc
)

## tools
add_subdirectory(src/tools/epee)
add_subdirectory(src/tools/common_basic)
add_subdirectory(src/tools/common)
add_subdirectory(src/tools/serialization)

## math
add_subdirectory(src/math/crypto)
add_subdirectory(src/math/ringct)

## cryptonote
add_subdirectory(src/cryptonote/basic)
add_subdirectory(src/cryptonote/tx)
add_subdirectory(src/cryptonote/core)
add_subdirectory(src/cryptonote/protocol)

## network
add_subdirectory(src/network/type)
add_subdirectory(src/network/rpc)
add_subdirectory(src/network/p2p)

## wallet
add_subdirectory(src/wallet/mnemonics)
add_subdirectory(src/wallet/device)
add_subdirectory(src/wallet/logic)
add_subdirectory(src/wallet/api)
add_subdirectory(src/wallet/common)
add_subdirectory(src/wallet/rpc)
add_subdirectory(src/wallet/cli)

## database
set(DATABASE lmdb)
set(BLOCKCHAIN_DB DB_LMDB)
add_definitions("-DDEFAULT_DB_TYPE=\"lmdb\"")
add_definitions("-DBLOCKCHAIN_DB=${BLOCKCHAIN_DB}")

include_directories(vendor/liblmdb)
add_subdirectory(vendor/liblmdb)
add_subdirectory(src/database)

## daemon
add_subdirectory(src/daemon)




# test
if(BUILD_TESTING)
  include(CTest)

  include_directories(tests)
  add_subdirectory(tests/hash)

  find_package(GTest REQUIRED)
  add_subdirectory(tests/unit_tests)
  # add_subdirectory(tests/core_tests)
endif()
