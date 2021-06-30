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

add_library( epee
  src/hex.cpp
  src/abstract_http_client.cpp
  src/mlog.cpp
  src/net_utils_base.cpp
  src/string_tools.cpp
  src/wipeable_string.cpp
  src/levin_base.cpp
  src/memwipe.cpp
  src/connection_basic.cpp
  src/buffer.cpp
  src/file_io_utils.cpp
  src/net_ssl.cpp
  src/console_handler.cpp
  src/time_helper.cpp
  src/misc_os_dependent.cpp
)

target_link_libraries( epee
  easylogging
  epee_net_basic
  ${OPENSSL_LIBRARIES}
)

add_library( epee_net_basic
  src/net/net_parse_helpers.cpp
)

add_library( epee_net
  src/net/http_protocol_handler.cpp
  src/net/net_helper.cpp
  src/net/http_client.cpp
)

target_link_libraries( epee_net
  epee_net_basic
)

add_library( epee_storage_basic
  src/storages/parserse_base_utils.cpp
)

add_library( epee_storage
  src/storages/portable_storage.cpp
  src/storages/portable_storage_from_json.cpp
  src/storages/portable_storage_from_bin.cpp
)

target_link_libraries( epee_storage
  epee_storage_basic
  epee
)

if (USE_READLINE AND (GNU_READLINE_FOUND))
  add_library( epee_readline
    src/readline_buffer.cpp
  )

  target_link_libraries( epee_readline
    easylogging
    ${GNU_READLINE_LIBRARY}
  )

  target_link_libraries( epee
    epee_readline
  )
endif()

