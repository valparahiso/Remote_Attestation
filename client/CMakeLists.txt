cmake_minimum_required(VERSION 3.10)
enable_language(C CXX ASM)

# check if SDK has been built and KEYSTONE_SDK_DIR environment variable exists
if (NOT DEFINED ENV{KEYSTONE_SDK_DIR})
  message(FATAL_ERROR "Please set KEYSTONE_SDK_DIR environment variable to an installed SDK path")
endif()
set(KEYSTONE_SDK_DIR $ENV{KEYSTONE_SDK_DIR})

if (NOT DEFINED ENV{LIBSODIUM_CLIENT_DIR})
  message(FATAL_ERROR "Please set LIBSODIUM_CLIENT_DIR")
endif()
set(LIBSODIUM_CLIENT_DIR $ENV{LIBSODIUM_CLIENT_DIR})

include($ENV{KEYSTONE_SDK_DIR}/cmake/macros.cmake)

if(RISCV32)
  message(STATUS "riscv32")
  set(BITS 32)
else()
  message(STATUS "riscv64")
  set(BITS 64)
endif()

use_riscv_toolchain(${BITS})

# export include directory
include_directories(include
  ${LIBSODIUM_CLIENT_DIR}/include
  ${KEYSTONE_SDK_DIR}/include
  ${KEYSTONE_SDK_DIR}/include/host
  ${KEYSTONE_SDK_DIR}/include/edge
  ${KEYSTONE_SDK_DIR}/include/verifier)

# set paths to the libraries
set(KEYSTONE_LIB_HOST ${KEYSTONE_SDK_DIR}/lib/libkeystone-host.a)
set(KEYSTONE_LIB_EDGE ${KEYSTONE_SDK_DIR}/lib/libkeystone-edge.a)
set(KEYSTONE_LIB_VERIFIER ${KEYSTONE_SDK_DIR}/lib/libkeystone-verifier.a)
set(KEYSTONE_LIB_EAPP ${KEYSTONE_SDK_DIR}/lib/libkeystone-eapp.a)
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)

# find program "makeself"
find_program(MAKESELF makeself)

# trusted client
add_executable(trusted_client.riscv
  trusted_client/client.cpp
  trusted_client/trusted_client.cpp
  include/enclave_expected_hash.h
  include/sm_expected_hash.h
)

target_link_libraries(trusted_client.riscv
  ${KEYSTONE_LIB_VERIFIER}
  ${LIBSODIUM_CLIENT_DIR}/.libs/libsodium.a)


#find_package(Threads REQUIRED)

#target_link_libraries(trusted_client.riscv Threads::Threads)

#find_package(SQLite3 REQUIRED CONFIG) 
#target_link_libraries(trusted_client.riscv SQLite::SQLite3)

