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


add_library(network_rpc_base
  rpc_args.cpp
  rpc_handler.cpp
  core_rpc_server_error_codes.cpp
  )

if(OpenCL_FOUND)
target_link_libraries(network_rpc_base
   OpenCL::OpenCL
  )
endif()

add_library(network_rpc
  core_rpc_server.cpp
  rpc_version_str.cpp
  )

target_link_libraries(network_rpc
  network_rpc_base
  cryptonote_tx
  cryptonote_core
)


add_library(daemon_messages
  message.cpp
  daemon_messages.cpp
)

add_library(daemon_rpc_server
  daemon_handler.cpp
)

# install(TARGETS network_rpc_base)
# install(TARGETS network_rpc)
# install(TARGETS daemon_rpc_server)
# install(TARGETS daemon_messages)
