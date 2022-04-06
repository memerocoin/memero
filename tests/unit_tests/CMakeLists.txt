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

add_executable(unit_tests_tools
  apply_permutation.cpp
  # base58.cpp
  # chacha.cpp
  command_line.cpp
  random.cpp
  # expect.cpp
  get_xtype_from_string.cpp
  varint.cpp
  threadpool.cpp
  crypto.cpp
  hashchain.cpp
  levin.cpp
  # epee_boosted_tcp_server.cpp
  epee_serialization.cpp
)

add_executable(test_notifier test_notifier.cpp)
add_dependencies(unit_tests_tools test_notifier)

target_link_libraries(unit_tests_tools
  epee
  tools_common
  epee_storage
  network_type 
  math_crypto
  ${Boost_PROGRAM_OPTIONS_LIBRARY}
  GTest::gtest
  GTest::gtest_main
  OpenCL::OpenCL
  sha3_iuf
  )


gtest_discover_tests(
  unit_tests_tools
)


add_executable(unit_tests_basic
  # device.cpp
  account.cpp
  mnemonics.cpp
  # bulletproofs.cpp
  # multiexp.cpp
)

target_link_libraries(unit_tests_basic
  cryptonote_basic
  wallet_mnemonics
  tools_serialization
  epee_storage
  version
  ${Boost_PROGRAM_OPTIONS_LIBRARY}
  GTest::gtest
  GTest::gtest_main
  math_ringct
)

gtest_discover_tests(
  unit_tests_basic
)



set_property(
  SOURCE main.cpp
  PROPERTY COMPILE_FLAGS -DDEFAULT_DATA_DIR='"${CMAKE_SOURCE_DIR}/tests/data"'
)

add_executable(unit_tests_core
  main.cpp

#  epee_levin_protocol_handler_async.cpp
#  parse_amount.cpp

  # block_queue.cpp
  difficulty.cpp
  epee_utils.cpp
  json_serialization.cpp
  net.cpp
# node_server.cpp
# // could fail
# output_size_histogram.cpp 
  ringct.cpp
  rpc_version_str.cpp
  slow_memmem.cpp
  test_peerlist.cpp
  test_protocol_pack.cpp
  test_tx_utils.cpp

#  // disabled since we have different block format (different hash function)
#  blockchain_db.cpp
)

target_link_libraries(unit_tests_core
  math_ringct
  cryptonote_protocol
  cryptonote_core
  database
  network_rpc
  network_type
  tools_serialization
  network_p2p
  epee_storage
  epee_net_p2p
  version

  ${Boost_PROGRAM_OPTIONS_LIBRARY}
  GTest::gtest
  GTest::gtest_main
)

gtest_discover_tests(
  unit_tests_core
)


add_executable(unit_tests_wallet_basic
  serialization.cpp
)

target_link_libraries(unit_tests_wallet_basic
  wallet_logic
  tools_serialization
  epee_storage
  epee_net
  ${Boost_PROGRAM_OPTIONS_LIBRARY}
  GTest::gtest
  GTest::gtest_main
)

gtest_discover_tests(
  unit_tests_wallet_basic
)



add_executable(unit_tests_wallet
  # output_selection.cpp
  subaddress.cpp
)

target_link_libraries(unit_tests_wallet
  wallet_api
  epee_net
  ${Boost_PROGRAM_OPTIONS_LIBRARY}
  GTest::gtest
  GTest::gtest_main
)

gtest_discover_tests(
  unit_tests_wallet
)




