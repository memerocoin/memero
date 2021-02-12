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

include(Version)
add_library(version ${CMAKE_BINARY_DIR}/version.cpp)
add_dependencies(version genversion)

add_subdirectory(math/crypto)
add_subdirectory(math/ringct)

add_subdirectory(tools/common)
add_subdirectory(tools/daemonizer)
add_subdirectory(tools/epee)
add_subdirectory(tools/serialization)

add_subdirectory(cryptonote/basic)
add_subdirectory(cryptonote/core)
add_subdirectory(cryptonote/protocol)

add_subdirectory(database/interface)
add_subdirectory(database/helper/lmdb)

add_subdirectory(network/type)
add_subdirectory(network/rpc)
add_subdirectory(network/p2p)

add_subdirectory(daemon)

add_subdirectory(wallet/mnemonics)
add_subdirectory(wallet/device)
add_subdirectory(wallet/logic)
add_subdirectory(wallet/rpc)
add_subdirectory(wallet/cli)
