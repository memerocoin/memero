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
cmake_minimum_required(VERSION 3.7.0)
message(STATUS "CMake version ${CMAKE_VERSION}")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(INSERT CMAKE_MODULE_PATH 0
  "${CMAKE_CURRENT_SOURCE_DIR}/etc/cmake")

project(lolnero)




# tools
option (USE_CCACHE "Use ccache if a usable instance is found" ON)
if (USE_CCACHE)
	include(FindCcache) # Has to be included after the project() macro, to be able to read the CXX variable.
else()
	message(STATUS "ccache deselected")
endif()

include(CheckCCompilerFlag)


# language
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

# build type
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
  message(STATUS "Setting default build type: ${CMAKE_BUILD_TYPE}")
endif()
string(TOLOWER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE_LOWER)


# arch

# set(OPT_FLAGS_RELEASE "-O2")

find_package(Threads REQUIRED)


# test
option(BUILD_TESTS "Build tests." OFF)
if(BUILD_TESTS)
  message(STATUS "Building tests")
  include(FindPythonInterp)
  find_package(PythonInterp)
  add_subdirectory(tests)
else()
  message(STATUS "Not building tests")
endif()





# libs

# openssl
find_package(OpenSSL REQUIRED)
message(STATUS "Using OpenSSL include dir at ${OPENSSL_INCLUDE_DIR}")
include_directories(${OPENSSL_INCLUDE_DIR})

# boost
find_package(Boost 1.67 REQUIRED COMPONENTS system date_time serialization program_options)

include_directories(SYSTEM ${Boost_INCLUDE_DIRS})

# readline
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

# sodium
find_library(SODIUM_LIBRARY sodium)




# external

# Set default blockchain storage location:
# memory was the default in Cryptonote before Monero implemented LMDB, it still works but is unnecessary.
# set(DATABASE memory)
set(DATABASE lmdb)
message(STATUS "Using LMDB as default DB type")
set(BLOCKCHAIN_DB DB_LMDB)
add_definitions("-DDEFAULT_DB_TYPE=\"lmdb\"")
add_definitions("-DBLOCKCHAIN_DB=${BLOCKCHAIN_DB}")

add_definitions(-DAUTO_INITIALIZE_EASYLOGGINGPP)

add_subdirectory(external)

# lmdb
include_directories(${LMDB_INCLUDE})

# easylogging
include_directories(external/easylogging++)

# rapidjson
include_directories(external/rapidjson/include)





# wrap up
include_directories(
  external
  src/tools/epee/include
  src
  src/tools
  src/math
  src/network
)

add_subdirectory(src)


