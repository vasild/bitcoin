# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

configure_file(${CMAKE_SOURCE_DIR}/cmake/bitcoin-config.h.in config/bitcoin-config.h @ONLY)
add_compile_definitions(HAVE_CONFIG_H)
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(crypto)
add_subdirectory(univalue)
add_subdirectory(util)


add_library(bitcoin_consensus_sources INTERFACE)
target_sources(bitcoin_consensus_sources INTERFACE
  arith_uint256.cpp
  consensus/merkle.cpp
  consensus/tx_check.cpp
  hash.cpp
  primitives/block.cpp
  primitives/transaction.cpp
  pubkey.cpp
  script/interpreter.cpp
  script/script.cpp
  script/script_error.cpp
  uint256.cpp
  util/strencodings.cpp
)

# Stable, backwards-compatible consensus functionality
# also exposed as a shared library or a static one.
add_library(bitcoin_consensus STATIC EXCLUDE_FROM_ALL)
target_link_libraries(bitcoin_consensus
  PRIVATE
    core_interface
    bitcoin_consensus_sources
    bitcoin_crypto
    secp256k1
)
