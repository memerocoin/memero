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
include(CheckCCompilerFlag)

list(INSERT CMAKE_MODULE_PATH 0
  "${CMAKE_SOURCE_DIR}/cmake")

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

project(monero)




# tools
option (USE_CCACHE "Use ccache if a usable instance is found" ON)
if (USE_CCACHE)
	include(FindCcache) # Has to be included after the project() macro, to be able to read the CXX variable.
else()
	message(STATUS "ccache deselected")
endif()




# helpers
function (die msg)
  if (NOT WIN32)
    string(ASCII 27 Esc)
    set(ColourReset "${Esc}[m")
    set(BoldRed     "${Esc}[1;31m")
  else ()
    set(ColourReset "")
    set(BoldRed     "")
  endif ()

  message(FATAL_ERROR "${BoldRed}${msg}${ColourReset}")
endfunction ()




# language
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)
CHECK_C_COMPILER_FLAG(-std=c11 HAVE_C11)






# build type
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
  message(STATUS "Setting default build type: ${CMAKE_BUILD_TYPE}")
endif()
string(TOLOWER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE_LOWER)





# arch
string(TOLOWER "${ARCH}" ARM_ID)
string(SUBSTRING "${ARM_ID}" 0 3 ARM_TEST)

if (ARM_ID STREQUAL "aarch64" OR ARM_ID STREQUAL "arm64" OR ARM_ID STREQUAL "armv8-a")
  set(ARM 1)
  set(ARM8 1)
  set(ARCH "armv8-a")
endif()

set(OPT_FLAGS_RELEASE "-O2")

set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG ${OPT_FLAGS_RELEASE}")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG ${OPT_FLAGS_RELEASE}")

option(BUILD_64 "Build for 64-bit? 'OFF' builds for 32-bit." ON)

if(BUILD_64)
  set(ARCH_WIDTH "64")
else()
  set(ARCH_WIDTH "32")
endif()
message(STATUS "Building for a ${ARCH_WIDTH}-bit system")

if(ANDROID)
  set(ATOMIC libatomic.a)
endif()




# library type
option(STATIC "Link libraries statically" false)

if(STATIC)
  set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
endif()

if(STATIC)
  # STATIC already configures most deps to be linked in statically,
  # here we make more deps static if the platform permits it
  if (MINGW)
    # On Windows, this is as close to fully-static as we get:
    # this leaves only deps on /c/Windows/system32/*.dll
    set(STATIC_FLAGS "-static")
  elseif (NOT (APPLE OR FREEBSD OR OPENBSD OR DRAGONFLY))
    # On Linux, we don't support fully static build, but these can be static
    set(STATIC_FLAGS "-static-libgcc -static-libstdc++")
  endif()
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${STATIC_FLAGS} ")
endif()

if(STATIC)
  if(MINGW)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
  endif()

  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_STATIC_RUNTIME ON)
endif()


# This is a CMake built-in switch that concerns internal libraries
if (NOT DEFINED BUILD_SHARED_LIBS AND NOT STATIC AND CMAKE_BUILD_TYPE_LOWER STREQUAL "debug")
    set(BUILD_SHARED_LIBS ON)
endif()

if (BUILD_SHARED_LIBS)
  message(STATUS "Building internal libraries with position independent code")
  add_definitions("-DBUILD_SHARED_LIBS")
else()
  message(STATUS "Building internal libraries as static")
endif()




# flags
set(PIC_FLAG "-fPIC")

find_package(Threads REQUIRED)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

message(STATUS "Building on ${CMAKE_SYSTEM_PROCESSOR} for ${ARCH}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ARCH_FLAG}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${ARCH_FLAG}")

message(STATUS "Using C security hardening flags: ${C_SECURITY_FLAGS}")
message(STATUS "Using C++ security hardening flags: ${CXX_SECURITY_FLAGS}")
message(STATUS "Using linker security hardening flags: ${LD_SECURITY_FLAGS}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -D_GNU_SOURCE ${MINGW_FLAG} ${STATIC_ASSERT_FLAG} ${WARNINGS} ${C_WARNINGS} ${COVERAGE_FLAGS} ${PIC_FLAG} ${C_SECURITY_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GNU_SOURCE ${MINGW_FLAG} ${STATIC_ASSERT_CPP_FLAG} ${WARNINGS} ${CXX_WARNINGS} ${COVERAGE_FLAGS} ${PIC_FLAG} ${CXX_SECURITY_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LD_SECURITY_FLAGS} ${LD_BACKCOMPAT_FLAGS}")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${DEBUG_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${DEBUG_FLAGS}")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${RELEASE_FLAGS}")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${RELEASE_FLAGS}")




# trace
option(STACK_TRACE "Install a hook that dumps stack on exception" OFF)

# When possible, avoid stack tracing using libunwind in favor of using easylogging++.
if(STACK_TRACE)
  set(STACK_TRACE_LIB "easylogging++") # for diag output only
endif()





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
if(USE_READLINE AND NOT DEPENDS)
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

list(APPEND EXTRA_LIBRARIES ${CMAKE_DL_LIBS})

add_subdirectory(src)


