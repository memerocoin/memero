# Memero wallet RPC (non-custodial, localhost JSON-RPC)

# nlohmann_json is header-only; find it on the include path
find_package(nlohmann_json 3.2.0 QUIET)

add_executable(memero-wallet-rpc
  wallet_rpc_main.cpp
)

target_link_libraries(memero-wallet-rpc
  wallet_api
  wallet_common
  wallet_mnemonics
  network_type
  tools_common
  tools_serialization
  epee
  version
  nlohmann_json::nlohmann_json

  ${Boost_PROGRAM_OPTIONS_LIBRARY}
  ${Boost_SYSTEM_LIBRARY}
)
set_property(TARGET memero-wallet-rpc
  PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

set_property(TARGET memero-wallet-rpc
  PROPERTY OUTPUT_NAME "memero-wallet-rpc")

install(TARGETS memero-wallet-rpc DESTINATION bin)
