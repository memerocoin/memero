# Copyright (c) 2020-2021, The Lolnero Project

# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:

# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.

# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.

# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.




# cmake
cmake_minimum_required(VERSION 3.18.0)
project(lolnero)




# tools
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/etc/cmake)




# language
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)




# compiler
add_compile_options(-Wall)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wno-reorder-ctor)

elseif (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  add_compile_options(-Wno-sign-compare)
  add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-Wno-reorder>)

endif()

if (ANDROID)
  add_compile_options(-Wno-tautological-constant-out-of-range-compare)
  add_compile_options(-Wno-ambiguous-reversed-operator)
endif()





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
find_library(SODIUM_LIBRARY sodium REQUIRED)

## rapidjson
if (ANDROID)
  include_directories(vendor/rapidjson/include)
endif()

## opencl
option(USE_OPENCL "Build with OpenCL support." OFF)
if(USE_OPENCL)
  find_package(OpenCL REQUIRED)
endif()

if(OpenCL_FOUND)
  add_definitions(-DOpenCL)
endif()


# set include path
include_directories(
  src
  vendor/curve25519/cryptonote
  vendor/liblmdb
)




# let's go

## version
add_library(version src/version.cpp)

## tools
add_subdirectory(src/tools/epee)
add_subdirectory(src/tools/common)
add_subdirectory(src/tools/serialization)

## math
add_subdirectory(vendor/curve25519/cryptonote)
add_subdirectory(src/math/crypto)
add_subdirectory(src/math/ringct)
add_subdirectory(src/math/blockchain)

## cryptonote
add_subdirectory(src/cryptonote/basic)
add_subdirectory(src/cryptonote/tx)
add_subdirectory(src/cryptonote/core)
add_subdirectory(src/cryptonote/protocol)
add_subdirectory(src/cryptonote/miner)

## consensus
add_subdirectory(src/consensus)

## network
add_subdirectory(src/network/type)
add_subdirectory(src/network/rpc)
add_subdirectory(src/network/p2p)

## wallet
add_subdirectory(src/wallet/mnemonics)
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

add_subdirectory(vendor/liblmdb)
add_subdirectory(src/database)

## daemon
add_subdirectory(src/daemon)

## opencl miner
if(OpenCL_FOUND)
  add_subdirectory(src/opencl)
endif()




# test
if(BUILD_TESTING)
  find_package(OpenCL REQUIRED)

  include(CTest)

  include_directories(tests)

  find_package(GTest REQUIRED)
  add_subdirectory(tests/unit_tests)
  add_subdirectory(tests/quick_tests)
  # add_subdirectory(tests/core_tests)
endif()
