cmake_minimum_required(VERSION 3.10)

project(cpcd VERSION "4.1.4.0")
set(CPC_LIBRARY_API_VERSION "2")
set(CPC_PROTOCOL_VERSION "2")

find_package(Backtrace)
add_library(backtrace INTERFACE)
if(Backtrace_FOUND)
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/backtrace/backtrace.h" "#include <${Backtrace_HEADER}>\n")
  target_compile_definitions(backtrace INTERFACE HAVE_BACKTRACE)
  target_include_directories(backtrace INTERFACE "${CMAKE_CURRENT_BINARY_DIR}/backtrace")
  target_include_directories(backtrace INTERFACE ${Backtrace_INCLUDE_DIRS})
  target_link_libraries(backtrace INTERFACE ${Backtrace_LIBRARIES})
endif()

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR})
set(GIT_SHA1 "Unknown")
set(GIT_REFSPEC "Unknown")
include(GetGitRevisionDescription)
get_git_head_revision(GIT_REFSPEC GIT_SHA1 ALLOW_LOOKING_ABOVE_CMAKE_SOURCE_DIR)
add_definitions("-DGIT_SHA1=\"${GIT_SHA1}\"")
add_definitions("-DGIT_REFSPEC=\"${GIT_REFSPEC}\"")

### Require out-of-source builds
file(TO_CMAKE_PATH "${CMAKE_CURRENT_BINARY_DIR}/CMakeLists.txt" LOC_PATH)
if(EXISTS "${LOC_PATH}")
    message(FATAL_ERROR "You cannot build in a source directory (or any directory with a CMakeLists.txt file). Please make a build subdirectory.")
endif()

add_compile_options(-Wall -Wextra -Wconversion -Wmissing-declarations -Wsign-conversion -Wswitch-default)
add_library(cpc SHARED lib/sl_cpc.c)

if(COMPILE_LTTNG STREQUAL TRUE)
  message(STATUS "Building CPC library with LTTNG tracing enabled.")
  target_compile_definitions(cpc PUBLIC COMPILE_LTTNG)
  target_link_libraries(cpc dl lttng-ust)
endif()

target_include_directories(cpc PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_include_directories(cpc PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/autogen")
set_target_properties(cpc PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(cpc PROPERTIES SOVERSION ${CPC_LIBRARY_API_VERSION})
set_target_properties(cpc PROPERTIES PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/lib/sl_cpc.h")

include(GNUInstallDirs)
add_definitions(-DDEFAULT_CONFIG_FILE_PATH="${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR}/cpcd.conf")

set(TARGET_GROUP release CACHE STRING "Group to build")
set(WARN_AS_ERROR FALSE CACHE BOOL "Treat warnings as errors")
set(ENABLE_ENCRYPTION TRUE CACHE BOOL "Enable the encryption of the CPC link using MbedTLS")
set(ENABLE_GPIOD FALSE CACHE BOOL "Enable the gpiod interface using Libgpiod")

# Enable encryption support if the user requested it
if(ENABLE_ENCRYPTION)
  message(STATUS "Building CPCd with encryption enabled")
  add_definitions("-DENABLE_ENCRYPTION")
  SET(security_sources security/security.c
                       modes/binding.c
                       security/private/keys/keys.c
                       security/private/protocol/protocol.c
                       security/private/thread/command_synchronizer.c
                       security/private/thread/security_thread.c)
  find_package(MbedTLS REQUIRED)
  if(MBEDTLS_INCLUDE_DIR  AND  MBEDTLS_LIBRARIES)
    include_directories(${MBEDTLS_INCLUDE_DIR})
  else()
    message(FATAL_ERROR "Failed to find MbedTLS library")
  endif()
else()
  message(WARNING "Building CPCd with encryption disabled, removing MbedTLS dependency")
endif()

# Enable warnings as error
if(WARN_AS_ERROR)
  target_compile_options(cpc PRIVATE -Werror)
endif()

# Enable gpiod support if the user requested it
if (ENABLE_GPIOD)
  message(STATUS "Building CPCd with gpiod enabled")
  add_definitions(-DGPIO_GPIOD)
  SET(gpio_sources misc/gpio_gpiod.c)
  find_library(GPIOD_LIBRARY NAMES libgpiod.so)
  if (NOT GPIOD_LIBRARY)
    message(FATAL_ERROR "Failed to find gpiod library, install libgpiod-dev")
  endif()
else()
  message(STATUS "Building CPCd with gpiosysfs enabled")
  add_definitions(-DGPIO_SYSFS)
  SET(gpio_sources misc/gpio_sysfs.c)
endif()

# Build CPC Daemon if building for release or debug
if((TARGET_GROUP STREQUAL release) OR
   (TARGET_GROUP STREQUAL debug) OR
   (TARGET_GROUP STREQUAL blackbox_test) OR
   (TARGET_GROUP STREQUAL blackbox_test_spurious_reset) OR
   (TARGET_GROUP STREQUAL blackbox_test_large_buf) OR
   (TARGET_GROUP STREQUAL blackbox_test_nonce_overflow))
  message(STATUS "Building CPC Daemon")

  if((TARGET_GROUP STREQUAL debug) OR
     (TARGET_GROUP STREQUAL blackbox_test) OR
     (TARGET_GROUP STREQUAL blackbox_test_spurious_reset) OR
     (TARGET_GROUP STREQUAL blackbox_test_large_buf) OR
     (TARGET_GROUP STREQUAL blackbox_test_nonce_overflow))
    add_compile_options(-funwind-tables -rdynamic)
  endif()

  if(TARGET_GROUP STREQUAL blackbox_test_nonce_overflow)
    # 2^29 - 4
    add_definitions("-DSLI_CPC_SECURITY_NONCE_FRAME_COUNTER_RESET_VALUE=536870908")
    set(ENABLE_ENCRYPTION TRUE CACHE BOOL "" FORCE)
    set(RUN_TESTS_ENCRYPTED "TRUE" CACHE STRING "Run tests with encryption")
  endif()

  add_executable(cpcd
                      cpcd.conf
                      server_core/server_core.c
                      server_core/epoll/epoll.c
                      server_core/core/core.c
                      server_core/core/crc.c
                      server_core/core/hdlc.c
                      server_core/server/server.c
                      server_core/server/server_ready_sync.c
                      server_core/system_endpoint/system.c
                      server_core/system_endpoint/system_callbacks.c
                      driver/driver_spi.c
                      driver/driver_uart.c
                      driver/driver_xmodem.c
                      driver/driver_ezsp.c
                      driver/driver_kill.c
                      misc/errno_codename.c
                      misc/logging.c
                      misc/config.c
                      misc/sl_slist.c
                      misc/board_controller.c
                      misc/sleep.c
                      modes/firmware_update.c
                      modes/normal.c
                      modes/uart_validation.c
                      ${gpio_sources}
                      ${security_sources}
                      lib/sl_cpc.c
                      main.c)

  if(COMPILE_LTTNG STREQUAL TRUE)
    message(STATUS "Building CPC Daemon with LTTNG tracing enabled. Set ENABLE_LTTNG_TRACING=true in config file to activate it.")
    target_compile_definitions(cpcd PUBLIC COMPILE_LTTNG)
    target_link_libraries(cpcd dl lttng-ust)
  endif()

  if(WARN_AS_ERROR)
    target_compile_options(cpcd PRIVATE -Werror)
  endif()

  target_include_directories(cpcd PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/autogen")
  target_include_directories(cpcd PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_include_directories(cpcd PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/lib")
  target_link_libraries(cpcd backtrace)
  target_link_libraries(cpcd util)
  target_link_libraries(cpcd pthread)

  if(ENABLE_ENCRYPTION)
    target_link_libraries(cpcd ${MBEDTLS_LIBRARIES})
  endif()

  if(ENABLE_GPIOD)
    target_link_libraries(cpcd ${GPIOD_LIBRARY})
  endif()

  install(TARGETS cpc cpcd
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
          PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
          PRIVATE_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

  install(FILES cpcd.conf DESTINATION ${CMAKE_INSTALL_SYSCONFDIR} COMPONENT config)
endif()

# Build CPC Daemon for release, nothing to do
if(TARGET_GROUP STREQUAL release)
    message(STATUS "Building release version")

# Build CPC Daemon for debug, add debug flags
elseif(TARGET_GROUP STREQUAL debug)
    message(STATUS "Building debug version")
    set(CMAKE_BUILD_TYPE Debug)

# Build CPC Daemon for self tests
elseif((TARGET_GROUP STREQUAL unit_test) OR (TARGET_GROUP STREQUAL unit_test_with_valgrind))
    message(STATUS "Building unit tests")
    set(CMAKE_BUILD_TYPE Debug)
    add_definitions(-DUNIT_TESTING)
    enable_testing()
    include(CTest)

    if(NOT DEFINED UNITY_PATH)
      set(UNITY_SOURCES "${CMAKE_CURRENT_LIST_DIR}/../../../../util/third_party/unity")
    else()
      set(UNITY_SOURCES ${UNITY_PATH})
    endif()

    add_definitions(-DHOST_BUILD)
    add_library(unity STATIC ${UNITY_SOURCES}/src/unity.c)
    set_target_properties(unity PROPERTIES PUBLIC_HEADER ${UNITY_SOURCES}/src/unity.h)
    target_include_directories(unity PUBLIC ${UNITY_SOURCES}/src/)

    add_executable(cpc_unity
                            server_core/server_core.c
                            server_core/epoll/epoll.c
                            server_core/core/core.c
                            server_core/core/crc.c
                            server_core/core/hdlc.c
                            server_core/server/server.c
                            server_core/server/server_ready_sync.c
                            server_core/system_endpoint/system.c
                            server_core/system_endpoint/system_callbacks.c
                            security/security.c
                            security/private/keys/keys.c
                            security/private/protocol/protocol.c
                            security/private/thread/command_synchronizer.c
                            security/private/thread/security_thread.c
                            driver/driver_emul.c
                            driver/driver_kill.c
                            driver/driver_uart.c
                            lib/sl_cpc.c
                            modes/uart_validation.c
                            misc/errno_codename.c
                            misc/logging.c
                            misc/config.c
                            misc/sl_slist.c
                            misc/board_controller.c
                            misc/sleep.c
                            test/unity/endpoints.c
                            test/unity/ack.c
                            test/unity/crc.c
                            test/unity/read.c
                            test/unity/write.c
                            test/unity/hdlc.c
                            test/unity/reject.c
                            test/unity/security.c
                            test/unity/re_transmit.c
                            test/unity/cpc_unity_common.c
                            test/unity/main.c)

    target_include_directories(cpc_unity PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/autogen")
    target_include_directories(cpc_unity PRIVATE ${UNITY_SOURCES}/src/)
    target_include_directories(cpc_unity PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_include_directories(cpc_unity PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/lib")
    target_link_libraries(cpc_unity backtrace)
    target_link_libraries(cpc_unity pthread)
    target_link_libraries(cpc_unity unity)
    target_link_libraries(cpc_unity cpc)
    target_link_libraries(cpc_unity ${MBEDTLS_LIBRARIES})

    # Run the tests
    add_subdirectory(test/unity)

    # Build CPC Daemon for target tests
elseif(TARGET_GROUP STREQUAL target_test)
    message(STATUS "Building target tests")
    set(CMAKE_BUILD_TYPE Debug)
    add_definitions(-DTARGET_TESTING)

    add_definitions(-DSL_CLI_USE_STDIO)

    include_directories(test/target/)

    add_executable(cpc_target
                    server_core/server_core.c
                    server_core/epoll/epoll.c
                    server_core/core/core.c
                    server_core/core/crc.c
                    server_core/core/hdlc.c
                    server_core/server/server.c
                    server_core/server/server_ready_sync.c
                    server_core/system_endpoint/system.c
                    server_core/system_endpoint/system_callbacks.c
                    security/security.c
                    security/private/keys/keys.c
                    security/private/protocol/protocol.c
                    security/private/thread/command_synchronizer.c
                    security/private/thread/security_thread.c
                    driver/driver_uart.c
                    driver/driver_spi.c
                    driver/driver_xmodem.c
                    driver/driver_ezsp.c
                    driver/driver_kill.c
                    modes/uart_validation.c
                    misc/errno_codename.c
                    misc/logging.c
                    misc/config.c
                    misc/sl_slist.c
                    misc/sl_string.c
                    misc/board_controller.c
                    misc/sleep.c
                    ${gpio_sources}
                    ../../test/linux/common/src/sl_assert.c
                    ../../iostream/src/sl_iostream_stdio.c
                    ../../iostream/src/sl_iostream.c
                    ../../cli/src/sl_cli_arguments.c
                    ../../cli/src/sl_cli_command.c
                    ../../cli/src/sl_cli_input.c
                    ../../cli/src/sl_cli_io.c
                    ../../cli/src/sl_cli_tokenize.c
                    ../../cli/src/sl_cli.c
                    test/target/command_table.c
                    test/target/cpc_test_cmd.c
                    test/target/cpc_test_multithread.c
                    test/target/cpc_test_cmd_large_buf.c
                    test/target/cpc_test_multithread.c
                    lib/sl_cpc.c
                    test/target/main.c)

    target_include_directories(cpc_target PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/autogen")
    target_include_directories(cpc_target PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_include_directories(cpc_target PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/lib")
    target_include_directories(cpc_target PRIVATE ../../test/linux/common/inc
                                                  ../../test/linux/emlib/inc
                                                  ../../iostream/inc/
                                                  ../../cli/inc/
                                                  ../../cli/src/
                                                  misc/)
    target_link_libraries(cpc_target backtrace)
    target_link_libraries(cpc_target pthread)
    target_link_libraries(cpc_target cpc)

    if(ENABLE_ENCRYPTION)
      target_link_libraries(cpc_target ${MBEDTLS_LIBRARIES})
    endif()

    if(ENABLE_GPIOD)
      target_link_libraries(cpc_target ${GPIOD_LIBRARY})
    endif()

elseif(TARGET_GROUP STREQUAL blackbox_test)
    message(STATUS "Building blackbox_test")

    set(CMAKE_BUILD_TYPE Debug)
    include_directories(test/blackbox/)

    add_executable(lib_client
                   test/blackbox/cpc_lib_client.c)

    target_include_directories(lib_client PRIVATE lib/)
    target_include_directories(lib_client PRIVATE misc/)
    target_link_libraries(lib_client pthread)
    target_link_libraries(lib_client cpc)

    enable_testing()
    include(CTest)

    if(NOT DEFINED UNITY_PATH)
      set(UNITY_SOURCES "${CMAKE_CURRENT_LIST_DIR}/../../../../util/third_party/unity")
    else()
      set(UNITY_SOURCES ${UNITY_PATH})
    endif()

    add_definitions(-DHOST_BUILD)
    add_library(unity STATIC ${UNITY_SOURCES}/src/unity.c)
    set_target_properties(unity PROPERTIES PUBLIC_HEADER ${UNITY_SOURCES}/src/unity.h)
    target_include_directories(unity PUBLIC ${UNITY_SOURCES}/src/)

    target_link_libraries(lib_client cpc)
    target_link_libraries(lib_client unity)

    # Run the tests
    add_subdirectory(test/blackbox)

elseif(TARGET_GROUP STREQUAL blackbox_test_spurious_reset)
    message(STATUS "Building blackbox_test_spurious_reset")

    set(CMAKE_BUILD_TYPE Debug)
    include_directories(test/blackbox/)

    add_executable(lib_client
                   test/blackbox/cpc_lib_client.c)

    target_include_directories(lib_client PRIVATE lib/)
    target_include_directories(lib_client PRIVATE misc/)
    target_link_libraries(lib_client pthread)
    target_link_libraries(lib_client cpc)

    enable_testing()
    include(CTest)

    if(NOT DEFINED UNITY_PATH)
      set(UNITY_SOURCES "${CMAKE_CURRENT_LIST_DIR}/../../../../util/third_party/unity")
    else()
      set(UNITY_SOURCES ${UNITY_PATH})
    endif()

    add_definitions(-DHOST_BUILD)
    add_definitions(-DTEST_SECONDARY_CRASH)

    add_library(unity STATIC ${UNITY_SOURCES}/src/unity.c)
    set_target_properties(unity PROPERTIES PUBLIC_HEADER ${UNITY_SOURCES}/src/unity.h)
    target_include_directories(unity PUBLIC ${UNITY_SOURCES}/src/)

    target_link_libraries(lib_client cpc)
    target_link_libraries(lib_client unity)

    # Run the tests
    add_subdirectory(test/blackbox)

elseif(TARGET_GROUP STREQUAL blackbox_test_large_buf)
    message(STATUS "Building blackbox_test_large_buf")

    set(CMAKE_BUILD_TYPE Debug)
    include_directories(test/blackbox/)

    add_definitions(-DDATA_CHUNK_SIZE=4087)

    add_executable(lib_client
                   test/blackbox/cpc_lib_client.c)

    target_include_directories(lib_client PRIVATE lib/)
    target_include_directories(lib_client PRIVATE misc/)
    target_link_libraries(lib_client pthread)
    target_link_libraries(lib_client cpc)

    enable_testing()
    include(CTest)

    if(NOT DEFINED UNITY_PATH)
      set(UNITY_SOURCES "${CMAKE_CURRENT_LIST_DIR}/../../../../util/third_party/unity")
    else()
      set(UNITY_SOURCES ${UNITY_PATH})
    endif()

    add_definitions(-DHOST_BUILD)
    add_library(unity STATIC ${UNITY_SOURCES}/src/unity.c)
    set_target_properties(unity PROPERTIES PUBLIC_HEADER ${UNITY_SOURCES}/src/unity.h)
    target_include_directories(unity PUBLIC ${UNITY_SOURCES}/src/)

    target_link_libraries(lib_client cpc)
    target_link_libraries(lib_client unity)

    # Run the tests
    add_subdirectory(test/blackbox)
elseif(TARGET_GROUP STREQUAL blackbox_test_nonce_overflow)
    message(STATUS "Building blackbox_test")

    set(CMAKE_BUILD_TYPE Debug)
    include_directories(test/blackbox/)

    add_executable(lib_client
                   test/blackbox/cpc_lib_client_overflow.c)

    target_include_directories(lib_client PRIVATE lib/)
    target_include_directories(lib_client PRIVATE misc/)
    target_link_libraries(lib_client pthread)
    target_link_libraries(lib_client cpc)

    enable_testing()
    include(CTest)

    if(NOT DEFINED UNITY_PATH)
      set(UNITY_SOURCES "${CMAKE_CURRENT_LIST_DIR}/../../../../util/third_party/unity")
    else()
      set(UNITY_SOURCES ${UNITY_PATH})
    endif()

    add_definitions(-DHOST_BUILD)
    add_library(unity STATIC ${UNITY_SOURCES}/src/unity.c)
    set_target_properties(unity PROPERTIES PUBLIC_HEADER ${UNITY_SOURCES}/src/unity.h)
    target_include_directories(unity PUBLIC ${UNITY_SOURCES}/src/)

    target_link_libraries(lib_client cpc)
    target_link_libraries(lib_client unity)

    # Run the tests
    add_subdirectory(test/blackbox)

elseif(TARGET_GROUP STREQUAL libcpc_wrapper_test)
	add_library(cpc_wrapper SHARED test/libcpc_wrapper/sl_cpc_mock.c)
else()
    message(FATAL_ERROR "Given TARGET_GROUP unknown specify when running cmake.. i.g: -DTARGET_GROUP=release")
endif()

# Hash all files except those in the output folder
if (TARGET cpcd)
  get_target_property(CPCD_SOURCES cpcd SOURCES)
  foreach(file ${CPCD_SOURCES})
    file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/${file}" FILE_HASH)
    string(APPEND SOURCES_HASH "${FILE_HASH}")
    string(SHA256 SOURCES_HASH "${SOURCES_HASH}")
  endforeach()
  message(STATUS "Sources hash:${SOURCES_HASH}")
endif()

# Configure the version header file
configure_file(misc/version.h.in autogen/version.h)
