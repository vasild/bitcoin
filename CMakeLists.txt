# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# We are able to build on Ubuntu Bionic.
# On the other hand, some useful features lack:
#  - 3.11: add_library() and add_executable() commands can now be called without any sources
#          and will not complain as long as sources are added later via the target_sources()
#          command.
#  - 3.11: The target_*() commands learned to set the INTERFACE properties on Imported Targets.
#  - 3.12: The add_compile_definitions() command was added to set preprocessor definitions
#          at directory level. This supersedes add_definitions().
#  - 3.12: If the CONFIGURE_DEPENDS flag is specified, CMake will add logic to the main
#          build system check target to rerun the flagged GLOB commands at build time.
#  - 3.12: Object libraries can be linked to with target_link_libraries().
#  - 3.12: A new $<TARGET_EXISTS:...> generator expression has been added.
#  - 3.13: The target_link_options() command was created to specify link options for targets
#          and their dependents.
#  - 3.13: The target_link_libraries() command may now be called to modify targets created
#          outside the current directory.
#  - 3.14: The FindSQLite3 module was added to find the SQLite v3.x library.
#  - 3.15: A new imported target Boost::headers is now defined (same as Boost::boost).
#  - 3.18: The add_library() and add_executable() commands learned to create Alias Targets
#          referencing non-GLOBAL Imported Targets.
#  - 3.18: The CheckLinkerFlag module has been added to provide a facility to check validity
#          of link flags.
cmake_minimum_required(VERSION 3.10)

project("Bitcoin Core"
  VERSION 23.0.0
  DESCRIPTION "Bitcoin client software"
  LANGUAGES CXX C ASM
)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/module")

set(PACKAGE_NAME ${PROJECT_NAME})
set(PACKAGE_VERSION ${PROJECT_VERSION})
set(CLIENT_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CLIENT_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CLIENT_VERSION_BUILD ${PROJECT_VERSION_PATCH})
set(CLIENT_VERSION_IS_RELEASE "false")
set(PACKAGE_BUGREPORT "https://github.com/bitcoin/bitcoin/issues")
set(PACKAGE_URL "https://bitcoincore.org/")
set(COPYRIGHT_YEAR "2022")
set(COPYRIGHT_HOLDERS "The %s developers")
set(COPYRIGHT_HOLDERS_SUBSTITUTION ${PROJECT_NAME})
set(COPYRIGHT_HOLDERS_FINAL "The Bitcoin Core developers")

if(MSVC)
  set(CMAKE_CXX_STANDARD 20)
else()
  set(CMAKE_CXX_STANDARD 17)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Configurable options.
option(BUILD_DAEMON "Build bitcoind" ON)
option(BUILD_CLI "Build bitcoin-cli" ON)
option(BUILD_TX "Build bitcoin-tx" ON)
option(BUILD_UTIL "Build bitcoin-util" ON)
option(BUILD_BITCOINCONSENSUS_LIB "Build bitcoinconsensus shared library" ON)
option(BUILD_BITCOINKERNEL_LIB "Build experimental bitcoinkernel shared library" ON)
option(ENABLE_WALLET "Enable wallet" ON)
option(BUILD_WALLET_TOOL "Build bitcoin-wallet tool" ${ENABLE_WALLET})
option(REDUCE_EXPORTS "Attempt to reduce exported symbols in the resulting executables" OFF)
option(WERROR "Treat compiler warnings as errors" OFF)
option(BUILD_TESTS "Build test" ON)

include(TryAppendCompilerFlag)
include(TryAppendLinkerFlag)

# Define compiler flags for "Debug" build type
set(debug_c_flags "")
try_append_cflag(debug_c_flags "-g3")
if(debug_c_flags STREQUAL "")
  try_append_cflag(debug_c_flags "-g") # fallback to -g if -g3 is not available
endif()
try_append_cflag(debug_c_flags "-O0")
try_append_cflag(debug_c_flags "-ftrapv")
set(CMAKE_C_FLAGS_DEBUG "${debug_c_flags}" CACHE STRING
  "Flags used by the C compiler during \"Debug\" builds."
  FORCE
)
set(CMAKE_CXX_FLAGS_DEBUG "${debug_c_flags}" CACHE STRING
  "Flags used by the C++ compiler during \"Debug\" builds."
  FORCE
)

# Define custom "RelWithAsserts" build type
set(release_c_flags "")
try_append_cflag(release_c_flags "-O2")
try_append_cflag(release_c_flags "-g")
set(release_cxx_flags "")
try_append_cxxflag(release_cxx_flags "-O2")
try_append_cxxflag(release_cxx_flags "-g")
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  # All versions of gcc that we commonly use for building are subject to bug
  # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=90348. To work around that, set
  # -fstack-reuse=none for all gcc builds.
  try_append_cxxflag(release_cxx_flags "-fstack-reuse=none")
endif()
set(CMAKE_C_FLAGS_RELWITHASSERTS "${release_c_flags}" CACHE STRING
  "Flags used by the C compiler during \"RelWithAsserts\" builds."
  FORCE
)
set(CMAKE_CXX_FLAGS_RELWITHASSERTS "${release_cxx_flags}" CACHE STRING
  "Flags used by the C++ compiler during \"RelWithAsserts\" builds."
  FORCE
)
set(release_linker_flags "")
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  try_append_linker_flag(release_linker_flags "-Wl,--major-subsystem-version,6")
  try_append_linker_flag(release_linker_flags "-Wl,--minor-subsystem-version,1")
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  # These flags are specific to ld64, and may cause issues with other linkers.
  # For example: GNU ld will interpret -dead_strip as -de and then try and use
  # "ad_strip" as the symbol for the entry point.
  try_append_linker_flag(release_linker_flags "-Wl,-dead_strip")
  try_append_linker_flag(release_linker_flags "-Wl,-dead_strip_dylibs")
  try_append_linker_flag(release_linker_flags "-Wl,-headerpad_max_install_names")
endif()
set(CMAKE_EXE_LINKER_FLAGS_RELWITHASSERTS "${release_linker_flags}" CACHE STRING
  "Flags used for linking binaries during \"RelWithAsserts\" builds."
  FORCE
)
set(CMAKE_SHARED_LINKER_FLAGS_RELWITHASSERTS "${release_linker_flags}" CACHE STRING
  "Flags used by the shared libraries linker during \"RelWithAsserts\" builds."
  FORCE
)
# Define custom "RelHardened" build type
set(hardened_cxx_flags "${release_cxx_flags}")
try_append_cxxflag(hardened_cxx_flags "-Wstack-protector")
try_append_cxxflag(hardened_cxx_flags "-fstack-protector-all")
try_append_cxxflag(hardened_cxx_flags "-fcf-protection=full")
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
  # stack-clash-protection doesn't currently work, and likely should just be skipped for Windows.
  # See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=90458 for more details.
  try_append_cxxflag(hardened_cxx_flags "-fstack-clash-protection")
endif()
set(CMAKE_C_FLAGS_RELHARDENED "${release_c_flags}" CACHE STRING
  "Flags used by the C compiler during \"RelHardened\" builds."
  FORCE
)
set(CMAKE_CXX_FLAGS_RELHARDENED "${hardened_cxx_flags}" CACHE STRING
  "Flags used by the C++ compiler during \"RelHardened\" builds."
  FORCE
)
set(hardened_linker_flags "${release_linker_flags}")
try_append_linker_flag(hardened_linker_flags "-Wl,--enable-reloc-section")
try_append_linker_flag(hardened_linker_flags "-Wl,--dynamicbase")
try_append_linker_flag(hardened_linker_flags "-Wl,--nxcompat")
try_append_linker_flag(hardened_linker_flags "-Wl,--high-entropy-va")
try_append_linker_flag(hardened_linker_flags "-Wl,-z,relro")
try_append_linker_flag(hardened_linker_flags "-Wl,-z,now")
try_append_linker_flag(hardened_linker_flags "-Wl,-z,separate-code")
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  try_append_linker_flag(hardened_linker_flags "-Wl,-bind_at_load")
endif()
set(CMAKE_EXE_LINKER_FLAGS_RELHARDENED "${hardened_linker_flags}" CACHE STRING
  "Flags used for linking binaries during \"RelHardened\" builds."
  FORCE
)
set(CMAKE_SHARED_LINKER_FLAGS_RELHARDENED "${hardened_linker_flags}" CACHE STRING
  "Flags used by the shared libraries linker during \"RelHardened\" builds."
  FORCE
)
mark_as_advanced(
  CMAKE_C_FLAGS_DEBUG
  CMAKE_CXX_FLAGS_DEBUG

  CMAKE_C_FLAGS_RELWITHASSERTS
  CMAKE_CXX_FLAGS_RELWITHASSERTS
  CMAKE_EXE_LINKER_FLAGS_RELWITHASSERTS
  CMAKE_SHARED_LINKER_FLAGS_RELWITHASSERTS
  CMAKE_C_FLAGS_RELHARDENED
  CMAKE_CXX_FLAGS_RELHARDENED
  CMAKE_EXE_LINKER_FLAGS_RELHARDENED
  CMAKE_SHARED_LINKER_FLAGS_RELHARDENED
)
get_property(cached_cmake_build_type CACHE CMAKE_BUILD_TYPE PROPERTY TYPE)
if(cached_cmake_build_type)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
    STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo" "RelWithAsserts" "RelHardened"
  )
endif()
set(default_build_type "RelHardened")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to \"${default_build_type}\" as none was specified")
  set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_definitions(-DABORT_ON_FAILED_ASSUME)
  add_definitions(-DDEBUG)
  add_definitions(-DDEBUG_LOCKCONTENTION)
  add_definitions(-DDEBUG_LOCKORDER)
  add_definitions(-DRPC_DOC_CHECK)
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(REDUCE_EXPORTS)
  set(CMAKE_CXX_VISIBILITY_PRESET hidden)
  set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)
  if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    link_libraries(-Wl,--exclude-libs,ALL)
  endif()
endif()

if(WERROR)
  set(error_cxx_flags "")
  try_append_cxxflag(error_cxx_flags "-Werror")
  if(NOT CXX_SUPPORTS_WERROR)
    message(FATAL_ERROR "WERROR set but -Werror is not usable.")
  endif()

  # -Wreturn-type is broken in GCC for MinGW-w64.
  # https://sourceforge.net/p/mingw-w64/bugs/306/
  set(CMAKE_REQUIRED_FLAGS "-Werror=return-type")
  check_cxx_source_compiles("
    #include <cassert>
    int f() { assert(false); }
    int main() { return 0; }
    " WERROR_RETURN_TYPE_WORKS)
  if(NOT WERROR_RETURN_TYPE_WORKS)
    try_append_cxxflag(error_cxx_flags "-Wno-error=return-type")
  endif()
  set(CMAKE_REQUIRED_FLAGS)

  separate_arguments(error_cxx_flags)
  add_compile_options(${error_cxx_flags})
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-D_MT -DWIN32 -D_WINDOWS -D_WIN32_WINNT=0x0601 -D_WIN32_IE=0x0501 -DWIN32_LEAN_AND_MEAN)
  if(MSVC)
    set(CMAKE_DISABLE_PRECOMPILE_HEADERS ON)
    add_definitions(
      /utf-8
      /Zc:__cplusplus
      /DNOMINMAX
      /D_CRT_SECURE_NO_WARNINGS
      /D_SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
    )
    add_compile_options(/wd4018 /wd4244 /wd4267 /wd4273 /wd4715 /wd4805 /wd4834)
  endif()
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  add_definitions(-DMAC_OSX -DOBJC_OLD_DISPATCH_PROTOTYPES=0)
endif()

get_directory_property(common_compile_options COMPILE_OPTIONS)

if(CMAKE_CROSSCOMPILING)
  add_definitions(${CPPFLAGS_FROM_DEPENDS})
  set(cflags_from_depends_list ${CFLAGS_FROM_DEPENDS})
  separate_arguments(cflags_from_depends_list)
  foreach(c_flag ${cflags_from_depends_list})
    add_compile_options($<$<COMPILE_LANGUAGE:C>:${c_flag}>)
  endforeach()
  set(cxxflags_from_depends_list ${CXXFLAGS_FROM_DEPENDS})
  separate_arguments(cxxflags_from_depends_list)
  foreach(cxx_flag ${cxxflags_from_depends_list})
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:${cxx_flag}>)
  endforeach()
  link_libraries(${LDFLAGS_FROM_DEPENDS})
endif()

include(cmake/introspection.cmake)

include(cmake/subtree-minisketch.cmake)
include(cmake/subtree-secp256k1.cmake)

include(CheckStdFilesystem)
check_std_filesystem()

if(BUILD_DAEMON OR BUILD_CLI OR BUILD_TX OR BUILD_BITCOINKERNEL_LIB OR BUILD_WALLET_TOOL OR NOT WITH_GUI STREQUAL "no")
  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads REQUIRED)

  # Find Boost headers only.
  find_package(Boost 1.64.0 REQUIRED)
endif()

include(CrossPkgConfig)
if(BUILD_DAEMON OR BUILD_CLI OR NOT WITH_GUI STREQUAL "no")
  cross_pkg_check_modules(libevent REQUIRED libevent>=2.1.8 IMPORTED_TARGET)
  target_link_libraries(PkgConfig::libevent INTERFACE $<$<PLATFORM_ID:Windows>:iphlpapi ws2_32>)
endif()

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows" AND (BUILD_DAEMON OR NOT WITH_GUI STREQUAL "no"))
  cross_pkg_check_modules(libevent_pthreads REQUIRED libevent_pthreads>=2.1.8 IMPORTED_TARGET)
endif()

include(cmake/optional_qt.cmake)
include(cmake/optional.cmake)

add_subdirectory(src)

if(BUILD_TESTS)
  add_subdirectory(src/test)
endif()

set(abs_top_srcdir ${CMAKE_SOURCE_DIR})
set(abs_top_builddir ${CMAKE_BINARY_DIR})
set(EXEEXT ${CMAKE_EXECUTABLE_SUFFIX})
if(NOT ENABLE_WALLET)
  set(ENABLE_WALLET_TRUE \#)
endif()
if(NOT ENABLE_WALLET OR NOT WITH_SQLITE)
  set(USE_SQLITE_TRUE \#)
endif()
if(NOT ENABLE_WALLET OR NOT WITH_BDB)
  set(USE_BDB_TRUE \#)
endif()
if(NOT BUILD_CLI)
  set(BUILD_BITCOIN_CLI_TRUE \#)
endif()
if(NOT BUILD_UTIL)
  set(BUILD_BITCOIN_UTIL_TRUE \#)
endif()
if(NOT BUILD_WALLET_TOOL)
  set(BUILD_BITCOIN_WALLET_TRUE \#)
endif()
if(NOT BUILD_DAEMON)
  set(BUILD_BITCOIND_TRUE \#)
endif()
if(NOT WITH_ZMQ)
  set(ENABLE_ZMQ_TRUE \#)
endif()
if(NOT ENABLE_EXTERNAL_SIGNER)
  set(ENABLE_EXTERNAL_SIGNER_TRUE \#)
endif()
if(NOT USE_SYSCALL_SANDBOX)
  set(ENABLE_SYSCALL_SANDBOX_TRUE \#)
endif()
if(NOT ENABLE_TRACING)
  set(ENABLE_USDT_TRACEPOINTS_TRUE \#)
endif()
configure_file(test/config.ini.in test/config.ini @ONLY)
execute_process(COMMAND mkdir -p ${CMAKE_BINARY_DIR}/test/functional)
execute_process(COMMAND rm -f ${CMAKE_BINARY_DIR}/test/functional/test_runner.py)
execute_process(COMMAND ln -s ${CMAKE_SOURCE_DIR}/test/functional/test_runner.py ${CMAKE_BINARY_DIR}/test/functional/test_runner.py)

message("\n")
message("Configure summary")
message("=================")
message("Utility binaries:")
message("  bitcoin-cli ...................... ${BUILD_CLI}")
message("  bitcoin-tx ....................... ${BUILD_TX}")
message("  bitcoin-util ..................... ${BUILD_UTIL}")
message("Wallet functionality:")
message("  SQLite, descriptor wallets ....... ${WITH_SQLITE}")
message("  Berkeley DB, legacy wallets ...... ${WITH_BDB}")
message("  wallet tool ...................... ${BUILD_WALLET_TOOL}")
message("Optional packages:")
message("  GUI .............................. ${WITH_GUI}")
if(NOT WITH_GUI STREQUAL "no")
  message("  QR code (GUI) .................... ${WITH_QRENCODE}")
endif()
message("  external signer .................. ${WITH_EXTERNAL_SIGNER}")
message("  NAT-PMP .......................... ${WITH_NATPMP}")
message("  UPNP ............................. ${WITH_MINIUPNPC}")
message("  ZeroMQ ........................... ${WITH_ZMQ}")
message("  USDT tracing ..................... ${WITH_USDT}")
message("  experimental syscall sandbox ..... ${WITH_SECCOMP}")
message("")
if(CMAKE_CROSSCOMPILING)
  message("Cross compiling for ................ ${CMAKE_SYSTEM_NAME}, ${CMAKE_SYSTEM_PROCESSOR}")
endif()
get_directory_property(definitions COMPILE_DEFINITIONS)
message("Preprocessor defined macros ........ ${definitions}")
message("C compiler ......................... ${CMAKE_C_COMPILER_LAUNCHER} ${CMAKE_C_COMPILER}")
message("CFLAGS ............................. ${CMAKE_C_FLAGS} ${CFLAGS_FROM_DEPENDS}")
message("C++ compiler ....................... ${CMAKE_CXX_COMPILER_LAUNCHER} ${CMAKE_CXX_COMPILER}")
message("CXXFLAGS ........................... ${CMAKE_CXX_FLAGS} ${CXXFLAGS_FROM_DEPENDS}")
message("Common compile options ............. ${common_compile_options}")
if(DEFINED CMAKE_BUILD_TYPE)
  message("Build type:")
  message(" - configuration ................... ${CMAKE_BUILD_TYPE}")
  string(TOUPPER ${CMAKE_BUILD_TYPE} build_type)
  message(" - CFLAGS .......................... ${CMAKE_C_FLAGS_${build_type}}")
  message(" - CXXFLAGS ........................ ${CMAKE_CXX_FLAGS_${build_type}}")
  message(" - LDFLAGS for executables ......... ${CMAKE_EXE_LINKER_FLAGS_${build_type}}")
  message(" - LDFLAGS for shared libraries .... ${CMAKE_SHARED_LINKER_FLAGS_${build_type}}")
else()
  message("Available configurations ........... ${CMAKE_CONFIGURATION_TYPES}")
endif()
message("\n")
