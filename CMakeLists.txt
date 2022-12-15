cmake_minimum_required(VERSION 3.10)

project(cpcd
  VERSION "4.2.0.0"
  LANGUAGES C)
set(CPC_LIBRARY_API_VERSION "3")
set(CPC_PROTOCOL_VERSION "3")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake/modules")

### Require out-of-source builds
file(TO_CMAKE_PATH "${CMAKE_CURRENT_BINARY_DIR}/CMakeLists.txt" LOC_PATH)
if(EXISTS "${LOC_PATH}")
    message(FATAL_ERROR "You cannot build in a source directory (or any directory with a CMakeLists.txt file). Please make a build subdirectory.")
endif()

# Options
set(TARGET_GROUP release CACHE STRING "Group to build")
option(WARN_AS_ERROR "Treat warnings as errors")
option(ENABLE_ENCRYPTION "Enable the encryption of the CPC link using MbedTLS" TRUE)
option(USE_LEGACY_GPIO_SYSFS "Use the legacy GPIO sysfs instead of GPIO device" TRUE)
option(COMPILE_LTTNG "Enable LTTng tracing")
option(ENABLE_VALGRIND "Enable Valgrind in tests")

# Includes
include(cmake/GetGitRevisionDescription.cmake)
include(cmake/TargetStds.cmake)
include(cmake/Warnings.cmake)
include(GNUInstallDirs)

# Dependencies
find_package(Threads REQUIRED)
find_package(Backtrace)
if(ENABLE_ENCRYPTION)
  # Use the config file provided by MbedTLS v3.
  # Use TERMUX_MBEDTLS_PATH as an additional search path.
  set(TERMUX_MBEDTLS_PATH "$ENV{PREFIX}/lib/cmake")
  find_package(MbedTLS 3 QUIET CONFIG PATHS ${TERMUX_MBEDTLS_PATH})
  if(NOT MbedTLS_FOUND)
    unset(MbedTLS_FOUND)
    # Fallback to module search for MbedTLS v2.
    find_package(MbedTLS 2.7 MODULE QUIET REQUIRED COMPONENTS crypto)
  endif()
  message(STATUS "Found MbedTLS: v${MbedTLS_VERSION}")
endif()
if(NOT USE_LEGACY_GPIO_SYSFS)
  find_package(PkgConfig REQUIRED)
  pkg_search_module(Libgpiod REQUIRED IMPORTED_TARGET libgpiod)
endif()
if(COMPILE_LTTNG)
  find_package(LTTngUST REQUIRED)
endif()

find_path(Linux_INCLUDE_DIR "linux/version.h")
if(NOT Linux_INCLUDE_DIR)
  message(FATAL_ERROR "Linux headers not found")
endif()

set(GIT_SHA1 "Unknown")
set(GIT_REFSPEC "Unknown")
get_git_head_revision(GIT_REFSPEC GIT_SHA1 ALLOW_LOOKING_ABOVE_CMAKE_SOURCE_DIR)
add_definitions("-DGIT_SHA1=\"${GIT_SHA1}\"")
add_definitions("-DGIT_REFSPEC=\"${GIT_REFSPEC}\"")

if(WARN_AS_ERROR)
  target_compile_options(_Warnings INTERFACE -Werror)
endif()

add_library(backtrace INTERFACE)
if(Backtrace_FOUND)
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/backtrace/backtrace.h" "#include <${Backtrace_HEADER}>\n")
  target_compile_definitions(backtrace INTERFACE HAVE_BACKTRACE)
  target_include_directories(backtrace INTERFACE "${CMAKE_CURRENT_BINARY_DIR}/backtrace")
  target_include_directories(backtrace INTERFACE ${Backtrace_INCLUDE_DIRS})
  target_link_libraries(backtrace INTERFACE ${Backtrace_LIBRARIES})
endif()

add_library(cpc SHARED)
target_stds(cpc C 99 POSIX 2008)
target_link_libraries(cpc PRIVATE Interface::Warnings)
target_sources(cpc PRIVATE lib/sl_cpc.c)

if(COMPILE_LTTNG)
  message(STATUS "Building CPC library with LTTNG tracing enabled.")
  target_compile_definitions(cpc PRIVATE COMPILE_LTTNG)
  target_link_libraries(cpc PRIVATE LTTng::UST)
endif()

target_include_directories(cpc PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_include_directories(cpc PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/autogen")
set_target_properties(cpc PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(cpc PROPERTIES SOVERSION ${CPC_LIBRARY_API_VERSION})
set_target_properties(cpc PROPERTIES PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/lib/sl_cpc.h")

# CPCd Config file path
if(NOT DEFINED CPCD_CONFIG_FILE_PATH)
  set(CPCD_CONFIG_FILE_PATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR}/cpcd.conf)
endif()
add_definitions(-DCPCD_CONFIG_FILE_PATH="${CPCD_CONFIG_FILE_PATH}")
message(STATUS "CPCD_CONFIG_FILE_PATH=${CPCD_CONFIG_FILE_PATH}")

# CPC Socket directory
if(NOT DEFINED CPC_SOCKET_DIR)
  set(CPC_SOCKET_DIR /dev/shm)
endif()
add_definitions(-DCPC_SOCKET_DIR="${CPC_SOCKET_DIR}")
message(STATUS "CPC_SOCKET_DIR=${CPC_SOCKET_DIR}")

# Enable encryption support if the user requested it
if(ENABLE_ENCRYPTION)
  add_definitions("-DENABLE_ENCRYPTION")
  message(STATUS "Building CPCd with encryption enabled")
else()
  message(WARNING "Building CPCd with encryption disabled, removing MbedTLS dependency")
endif()

# Enable gpiod support if the user requested it
if(USE_LEGACY_GPIO_SYSFS)
  message(STATUS "Building CPCd with GPIO sysfs")
else()
  message(STATUS "Building CPCd with GPIO device")
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
    add_compile_options(-funwind-tables)
    # CMake<3.13 does not support target_link_options
    target_link_libraries(backtrace INTERFACE "-rdynamic")
  endif()

  if(TARGET_GROUP STREQUAL blackbox_test_nonce_overflow)
    # 2^29 - 4
    add_definitions("-DSLI_CPC_SECURITY_NONCE_FRAME_COUNTER_RESET_VALUE=536870908")
    set(ENABLE_ENCRYPTION TRUE CACHE BOOL "" FORCE)
    set(RUN_TESTS_ENCRYPTED "TRUE" CACHE STRING "Run tests with encryption")
  endif()

  # CMake<3.11 requires two arguments
  add_executable(cpcd main.c)
  target_stds(cpcd C 99 POSIX 2008)
  target_link_libraries(cpcd PRIVATE Interface::Warnings)
  target_sources(cpcd PRIVATE
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
                      misc/utils.c
                      misc/sl_slist.c
                      misc/board_controller.c
                      misc/sleep.c
                      modes/firmware_update.c
                      modes/normal.c
                      modes/uart_validation.c
                      lib/sl_cpc.c)

  if(COMPILE_LTTNG)
    message(STATUS "Building CPC Daemon with LTTNG tracing enabled. Set ENABLE_LTTNG_TRACING=true in config file to activate it.")
    target_compile_definitions(cpcd PRIVATE COMPILE_LTTNG)
    target_link_libraries(cpcd PRIVATE LTTng::UST)
  endif()

  target_include_directories(cpcd PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/autogen")
  target_include_directories(cpcd PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_include_directories(cpcd PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/lib")
  target_link_libraries(cpcd PRIVATE Threads::Threads)
  target_link_libraries(cpcd PRIVATE backtrace)

  if(ENABLE_ENCRYPTION)
    target_link_libraries(cpcd PRIVATE MbedTLS::mbedcrypto)
    target_sources(cpcd PRIVATE
      modes/binding.c
      security/private/keys/keys.c
      security/private/protocol/protocol.c
      security/private/thread/command_synchronizer.c
      security/private/thread/security_thread.c
      security/security.c)
  endif()
  if(USE_LEGACY_GPIO_SYSFS)
    target_compile_definitions(cpcd PRIVATE USE_LEGACY_GPIO_SYSFS)
    target_sources(cpcd PRIVATE misc/gpio_sysfs.c)
  else()
    target_link_libraries(cpcd PRIVATE PkgConfig::Libgpiod)
    target_sources(cpcd PRIVATE misc/gpio_gpiod.c)
  endif()

  # Hash all files except those in the output folder
  get_target_property(CPCD_SOURCES cpcd SOURCES)
  foreach(file ${CPCD_SOURCES})
    file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/${file}" FILE_HASH)
    string(APPEND SOURCES_HASH "${FILE_HASH}")
    string(SHA256 SOURCES_HASH "${SOURCES_HASH}")
  endforeach()
  message(STATUS "Sources hash: ${SOURCES_HASH}")

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
                            misc/utils.c
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
    target_link_libraries(cpc_unity PRIVATE Threads::Threads MbedTLS::mbedcrypto)
    target_link_libraries(cpc_unity PRIVATE backtrace)
    target_link_libraries(cpc_unity PRIVATE cpc unity)

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
                    misc/utils.c
                    misc/sl_slist.c
                    misc/sl_string.c
                    misc/board_controller.c
                    misc/sleep.c
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
    target_link_libraries(cpc_target PRIVATE Threads::Threads)
    target_link_libraries(cpc_target PRIVATE backtrace)
    target_link_libraries(cpc_target PRIVATE cpc)
    if(ENABLE_ENCRYPTION)
      target_link_libraries(cpc_target PRIVATE MbedTLS::mbedcrypto)
    endif()
    if(USE_LEGACY_GPIO_SYSFS)
      target_compile_definitions(cpc_target PRIVATE USE_LEGACY_GPIO_SYSFS)
      target_sources(cpc_target PRIVATE misc/gpio_sysfs.c)
    else()
      target_link_libraries(cpc_target PRIVATE PkgConfig::Libgpiod)
      target_sources(cpc_target PRIVATE misc/gpio_gpiod.c)
    endif()

elseif(TARGET_GROUP STREQUAL blackbox_test)
    message(STATUS "Building blackbox_test")

    set(CMAKE_BUILD_TYPE Debug)
    include_directories(test/blackbox/)

    add_executable(lib_client
                   test/blackbox/cpc_lib_client.c)

    target_include_directories(lib_client PRIVATE lib/)
    target_include_directories(lib_client PRIVATE misc/)
    target_include_directories(lib_client PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/autogen")
    target_link_libraries(lib_client PRIVATE Threads::Threads)
    target_link_libraries(lib_client PRIVATE cpc)

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

    target_link_libraries(lib_client PRIVATE cpc unity)

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
    target_include_directories(lib_client PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/autogen")
    target_link_libraries(lib_client PRIVATE Threads::Threads)
    target_link_libraries(lib_client PRIVATE cpc)

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

    target_link_libraries(lib_client PRIVATE cpc unity)

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
    target_include_directories(lib_client PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/autogen")
    target_link_libraries(lib_client PRIVATE Threads::Threads)
    target_link_libraries(lib_client PRIVATE cpc)

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

    target_link_libraries(lib_client PRIVATE cpc unity)

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
    target_include_directories(lib_client PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/autogen")
    target_link_libraries(lib_client PRIVATE Threads::Threads)
    target_link_libraries(lib_client PRIVATE cpc)

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

    target_link_libraries(lib_client PRIVATE cpc unity)

    # Run the tests
    add_subdirectory(test/blackbox)

elseif(TARGET_GROUP STREQUAL libcpc_wrapper_test)
	add_library(cpc_wrapper SHARED test/libcpc_wrapper/sl_cpc_mock.c)
else()
    message(FATAL_ERROR "Given TARGET_GROUP unknown specify when running cmake.. i.g: -DTARGET_GROUP=release")
endif()

# Configure the version header file
configure_file(misc/version.h.in autogen/version.h)

