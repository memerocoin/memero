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
  base58.cpp
  chacha.cpp
  command_line.cpp
  random.cpp
  expect.cpp
  get_xtype_from_string.cpp
  logging.cpp
  mul_div.cpp
  notify.cpp
  varint.cpp
  wipeable_string.cpp
  aligned.cpp
  threadpool.cpp
  memwipe.cpp
  crypto.cpp
  hashchain.cpp
  decompose_amount_into_digits.cpp
  levin.cpp
  epee_boosted_tcp_server.cpp
  epee_serialization.cpp
)

add_executable(unit_tests_basic
  device.cpp
  account.cpp
  mnemonics.cpp
  bulletproofs.cpp
  multiexp.cpp
)

add_executable(unit_tests_core
  main.cpp

#  blockchain_db.cpp
#  block_queue.cpp
#  difficulty.cpp
#  epee_levin_protocol_handler_async.cpp
#  node_server.cpp
#  output_distribution.cpp
#  parse_amount.cpp
#  ringct.cpp

  epee_utils.cpp
  json_serialization.cpp
  lmdb.cpp
  net.cpp
  slow_memmem.cpp
  test_tx_utils.cpp
  test_peerlist.cpp
  test_protocol_pack.cpp
  tx_proof.cpp
  rpc_version_str.cpp
  )

add_executable(unit_tests_wallet
  # uri.cpp
  # output_selection.cpp
  subaddress.cpp
  serialization.cpp
  )

target_link_libraries(unit_tests_tools
  PRIVATE
    epee
    common
    common_basic
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    GTest::gtest
    GTest::gtest_main
)

target_link_libraries(unit_tests_basic
  PRIVATE
    epee
    common
    common_basic
    cryptonote_basic
    mnemonics
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    GTest::gtest
    GTest::gtest_main
)

target_link_libraries(unit_tests_core
  PRIVATE
    ringct
    cryptonote_protocol
    cryptonote_core
    # blockchain_db
    lmdb_lib
    rpc
    net
    serialization
    p2p
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    GTest::gtest
    GTest::gtest_main
    )

target_link_libraries(unit_tests_wallet
  PRIVATE
    wallet_api
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    GTest::gtest
    GTest::gtest_main
    )

set_property(TARGET unit_tests_basic
  PROPERTY
    FOLDER "tests"
    )

set_property(TARGET unit_tests_wallet
  PROPERTY
    FOLDER "tests"
    )

SET_PROPERTY(
  SOURCE main.cpp
  PROPERTY COMPILE_FLAGS -DDEFAULT_DATA_DIR="\\"${CMAKE_SOURCE_DIR}/tests/data\\""
)

add_executable(test_notifier test_notifier.cpp)
set_property(TARGET test_notifier PROPERTY FOLDER "tests")

add_test(
  NAME    unit_tests_tools
  COMMAND unit_tests_tools
)

add_test(
  NAME    unit_tests_basic
  COMMAND unit_tests_basic
)

add_test(
  NAME    unit_tests_core
  COMMAND unit_tests_core
)

add_test(
  NAME    unit_tests_wallet
  COMMAND unit_tests_wallet
  )

