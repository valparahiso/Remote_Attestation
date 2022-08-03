add_executable(attester_eapp.eapp_riscv
  attester_eapp.c
  edge_wrapper.c
  calculator.c
  channel.c)

include_directories(include
  ${KEYSTONE_SDK_DIR}/include/app)

target_link_libraries(attester_eapp.eapp_riscv
  ${KEYSTONE_LIB_EDGE}
  ${KEYSTONE_LIB_EAPP}
  ${LIBSODIUM_DIR}/.libs/libsodium.a)

set_target_properties(attester_eapp.eapp_riscv
  PROPERTIES LINK_FLAGS "-nostdlib -static -T ${CMAKE_CURRENT_SOURCE_DIR}/app.lds")
