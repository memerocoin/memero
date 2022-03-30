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
cmake_minimum_required(VERSION 3.20.0)
project(lolnero)




# language
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)




# compiler
add_compile_options(-Wall)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  add_compile_options(-Wno-sign-compare)

  if (CMAKE_SYSTEM_PROCESSOR MATCHES "(aarch64)")
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-mno-outline-atomics>)
    message("Added GCC workaround flag -mno-outline-atomics")
  endif ()
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

## boost
find_package(Boost 1.74 REQUIRED COMPONENTS system serialization program_options)
include_directories(${Boost_INCLUDE_DIRS})

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
  vendor/SHA3IUF
)





# libs

## tools
add_subdirectory(src/tools/epee)

## math
add_subdirectory(vendor/curve25519/cryptonote)
add_subdirectory(vendor/SHA3IUF)
add_subdirectory(src/math/hash)
add_subdirectory(src/math/group)
add_subdirectory(src/math/crypto)
add_subdirectory(src/math/ringct)

# bins
option(ONLY_LIB "Only build libraries" OFF)
if(NOT ONLY_LIB)

## version
add_subdirectory(src/config/version)

## tools
add_subdirectory(src/tools/common)
add_subdirectory(src/tools/serialization)

## math
add_subdirectory(src/math/blockchain)
add_subdirectory(src/math/consensus)

## cryptonote
add_subdirectory(src/cryptonote/basic)
add_subdirectory(src/cryptonote/tx)
add_subdirectory(src/cryptonote/core)
add_subdirectory(src/cryptonote/protocol)
add_subdirectory(src/cryptonote/miner)

## network
add_subdirectory(src/network/type)
add_subdirectory(src/network/rpc)
add_subdirectory(src/network/p2p)

## wallet
add_subdirectory(src/wallet/mnemonics)
add_subdirectory(src/wallet/logic)
add_subdirectory(src/wallet/api)
add_subdirectory(src/wallet/common)
add_subdirectory(src/wallet/cli)

## database
set(DATABASE lmdb)
set(BLOCKCHAIN_DB DB_LMDB)
add_definitions("-DDEFAULT_DB_TYPE=\"lmdb\"")
add_definitions("-DBLOCKCHAIN_DB=${BLOCKCHAIN_DB}")

add_subdirectory(vendor/liblmdb)

## daemon
add_subdirectory(src/daemon/database)
add_subdirectory(src/daemon/rpc)
add_subdirectory(src/daemon/cli)

## opencl miner
if(OpenCL_FOUND)
  add_subdirectory(src/math/hash/opencl)
endif()




# test

option(BUILD_TESTING "Build tests." OFF)
if(BUILD_TESTING)
  include(CTest)
  find_package(OpenCL REQUIRED)

  include_directories(tests)

  find_package(GTest REQUIRED)
  add_subdirectory(tests/unit_tests)
  add_subdirectory(tests/quick_tests)
  # add_subdirectory(tests/core_tests)
endif()


endif()
