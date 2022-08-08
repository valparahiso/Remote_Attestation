cmake_minimum_required(VERSION 3.10)
enable_language(C CXX ASM)

# check if SDK has been built and KEYSTONE_SDK_DIR environment variable exists
if (NOT DEFINED ENV{KEYSTONE_SDK_DIR})
  message(FATAL_ERROR "Please set KEYSTONE_SDK_DIR environment variable to an installed SDK path")
endif()
set(KEYSTONE_SDK_DIR $ENV{KEYSTONE_SDK_DIR})

if (NOT DEFINED ENV{LIBSODIUM_verifier_DIR})
  message(FATAL_ERROR "Please set LIBSODIUM_verifier_DIR")
endif()
set(LIBSODIUM_verifier_DIR $ENV{LIBSODIUM_verifier_DIR})

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
  ${LIBSODIUM_verifier_DIR}/include
  ${KEYSTONE_SDK_DIR}/include
  ${KEYSTONE_SDK_DIR}/include/host
  ${KEYSTONE_SDK_DIR}/include/edge
  ${KEYSTONE_SDK_DIR}/include/verifier
  /usr/local/lib)

# set paths to the libraries
set(KEYSTONE_LIB_HOST ${KEYSTONE_SDK_DIR}/lib/libkeystone-host.a)
set(KEYSTONE_LIB_EDGE ${KEYSTONE_SDK_DIR}/lib/libkeystone-edge.a)
set(KEYSTONE_LIB_VERIFIER ${KEYSTONE_SDK_DIR}/lib/libkeystone-verifier.a)
set(KEYSTONE_LIB_EAPP ${KEYSTONE_SDK_DIR}/lib/libkeystone-eapp.a)
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# find program "makeself"
find_program(MAKESELF makeself)

# trusted verifier
add_executable(trusted_verifier.riscv
  trusted_verifier/verifier.cpp
  trusted_verifier/trusted_verifier.cpp
  include/enclave_expected_hash.h
  include/sm_expected_hash.h
)

find_package(Sqlite3 REQUIRED)
include_directories(${SQLITE3_INCLUDE_DIRS})
target_link_libraries(trusted_verifier.riscv
  ${KEYSTONE_LIB_VERIFIER}
  ${LIBSODIUM_verifier_DIR}/.libs/libsodium.a
  ${SQLITE3_LIBRARIES})


#find_package(Threads REQUIRED)

#target_link_libraries(trusted_verifier.riscv Threads::Threads)

#find_package(SQLite3 REQUIRED CONFIG) 
#target_link_libraries(trusted_verifier.riscv SQLite::SQLite3)
