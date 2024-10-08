# Ubuntu 18.04 ships CMake 3.10
cmake_minimum_required(VERSION 3.10)

project(cpc-daemon
  VERSION "4.5.2.0"
  LANGUAGES C)

option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_TESTING "Build tests" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake/modules")
include(CTest)
include(GNUInstallDirs)
include("./cmake/GetGitRevisionDescription.cmake")
include("./cmake/Warnings.cmake")

option(USE_LEGACY_GPIO_SYSFS "Use the legacy GPIO sysfs instead of GPIO device" OFF)
option(ENABLE_ENCRYPTION "Enable the encryption of the CPC link using MbedTLS" ON)
option(COMPILE_LTTNG "Enable LTTng tracing" OFF)
option(ENABLE_VALGRIND "Enable Valgrind in tests" OFF)
option(TARGET_TESTING "Enable target testing" OFF)
set(CPC_LIBRARY_API_VERSION "3")
set(CPC_PROTOCOL_VERSION "5")
set(CPC_SOCKET_DIR "/dev/shm" CACHE STRING "CPC socket directory")
set(DEFAULT_INSTANCE_NAME "cpcd_0" CACHE STRING "Default instance name")
set(CPCD_CONFIG_FILE_PATH "${CMAKE_INSTALL_FULL_SYSCONFDIR}/cpcd.conf" CACHE STRING "CPCd config file")
set(CPCD_REBOOT_TIME_MS "2000" CACHE STRING "CPCd reboot time")

###

find_package(Backtrace)
find_package(PkgConfig)
find_package(Threads REQUIRED)

if(ENABLE_ENCRYPTION)
  # 1. Try pkg-config
  # 2. Try config file provided by MbedTLS starting from 3.0
  # 3. Try module search for MbedTLS
  if(PkgConfig_FOUND)
    pkg_search_module(MbedCrypto IMPORTED_TARGET mbedcrypto>=2.7)
  endif()
  if(MbedCrypto_FOUND)
    add_library(MbedTLS::mbedcrypto ALIAS PkgConfig::MbedCrypto)
  else()
    find_package(MbedTLS 3 QUIET CONFIG
      # For Termux
      PATHS "$ENV{PREFIX}/lib/cmake")
    if(NOT MbedTLS_FOUND)
      find_package(MbedTLS 2.7 MODULE REQUIRED
        COMPONENTS crypto)
    endif()
    message(STATUS "Found MbedTLS: v${MbedTLS_VERSION}")
  endif()
endif()

if(COMPILE_LTTNG)
  find_package(LTTngUST REQUIRED)
endif()

if(Backtrace_FOUND)
  file(WRITE "${PROJECT_BINARY_DIR}/backtrace/backtrace.h" "#include <${Backtrace_HEADER}>\n")
  add_library(backtrace INTERFACE)
  target_include_directories(backtrace INTERFACE "${PROJECT_BINARY_DIR}/backtrace")
  target_include_directories(backtrace INTERFACE ${Backtrace_INCLUDE_DIRS})
  target_link_libraries(backtrace INTERFACE ${Backtrace_LIBRARIES})
endif()

###

add_compile_options(-fno-omit-frame-pointer -fstack-protector-strong)
if(TARGET LTTng::UST)
  link_libraries(LTTng::UST)
endif()

if(TARGET backtrace)
  set(HAVE_BACKTRACE ON)
endif()

get_git_head_revision(GIT_REFSPEC GIT_SHA1 ALLOW_LOOKING_ABOVE_CMAKE_SOURCE_DIR)
configure_file("./misc/config.h.in" "config.h" @ONLY)
configure_file("./libcpc.pc.in" "libcpc.pc" @ONLY)

###

add_library(cpc)
set_target_properties(cpc PROPERTIES
  VERSION ${PROJECT_VERSION} SOVERSION ${CPC_LIBRARY_API_VERSION})
set_target_properties(cpc PROPERTIES
  C_STANDARD 99 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
target_compile_definitions(cpc PRIVATE _POSIX_C_SOURCE=200809L)
target_include_directories(cpc PRIVATE "${PROJECT_BINARY_DIR}")
target_include_directories(cpc PRIVATE "./include")
target_include_directories(cpc PUBLIC "./lib")
set_target_properties(cpc PROPERTIES PUBLIC_HEADER "./lib/sl_cpc.h")
target_sources(cpc PRIVATE
  "./lib/sl_cpc.c"
  "./misc/sl_slist.c"
  "./misc/sleep.c")
target_link_libraries(cpc PRIVATE Threads::Threads)

set(CPCD_SOURCES
  "${PROJECT_SOURCE_DIR}/driver/driver_ezsp.c"
  "${PROJECT_SOURCE_DIR}/driver/driver_kill.c"
  "${PROJECT_SOURCE_DIR}/driver/driver_spi.c"
  "${PROJECT_SOURCE_DIR}/driver/driver_uart.c"
  "${PROJECT_SOURCE_DIR}/driver/driver_xmodem.c"
  "${PROJECT_SOURCE_DIR}/misc/board_controller.c"
  "${PROJECT_SOURCE_DIR}/misc/config.c"
  "${PROJECT_SOURCE_DIR}/misc/exit.c"
  "${PROJECT_SOURCE_DIR}/misc/logging.c"
  "${PROJECT_SOURCE_DIR}/misc/sl_slist.c"
  "${PROJECT_SOURCE_DIR}/misc/sleep.c"
  "${PROJECT_SOURCE_DIR}/misc/utils.c"
  "${PROJECT_SOURCE_DIR}/modes/firmware_update.c"
  "${PROJECT_SOURCE_DIR}/modes/normal.c"
  "${PROJECT_SOURCE_DIR}/modes/uart_validation.c"
  "${PROJECT_SOURCE_DIR}/server_core/core/buffer.c"
  "${PROJECT_SOURCE_DIR}/server_core/core/core.c"
  "${PROJECT_SOURCE_DIR}/server_core/core/crc.c"
  "${PROJECT_SOURCE_DIR}/server_core/core/hdlc.c"
  "${PROJECT_SOURCE_DIR}/server_core/core/protocol.c"
  "${PROJECT_SOURCE_DIR}/server_core/core/protocol_v4.c"
  "${PROJECT_SOURCE_DIR}/server_core/core/protocol_v5.c"
  "${PROJECT_SOURCE_DIR}/server_core/epoll/epoll.c"
  "${PROJECT_SOURCE_DIR}/server_core/server/server.c"
  "${PROJECT_SOURCE_DIR}/server_core/server/server_ready_sync.c"
  "${PROJECT_SOURCE_DIR}/server_core/server_core.c"
  "${PROJECT_SOURCE_DIR}/server_core/system_endpoint/system.c")
if(USE_LEGACY_GPIO_SYSFS)
  list(APPEND CPCD_SOURCES "${PROJECT_SOURCE_DIR}/misc/gpio_sysfs.c")
else()
  list(APPEND CPCD_SOURCES "${PROJECT_SOURCE_DIR}/misc/gpio.c")
endif()
if(ENABLE_ENCRYPTION)
  list(APPEND CPCD_SOURCES
    "${PROJECT_SOURCE_DIR}/modes/binding.c"
    "${PROJECT_SOURCE_DIR}/security/private/keys/keys.c"
    "${PROJECT_SOURCE_DIR}/security/private/protocol/protocol.c"
    "${PROJECT_SOURCE_DIR}/security/private/thread/command_synchronizer.c"
    "${PROJECT_SOURCE_DIR}/security/private/thread/security_thread.c"
    "${PROJECT_SOURCE_DIR}/security/security.c")
endif()

add_executable(cpcd "./main.c")
set_target_properties(cpcd PROPERTIES
  C_STANDARD 99 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
target_compile_definitions(cpcd PRIVATE _GNU_SOURCE)
target_include_directories(cpcd PRIVATE "${PROJECT_BINARY_DIR}")
target_include_directories(cpcd PRIVATE "./include" ".")
target_sources(cpcd PRIVATE ${CPCD_SOURCES})
target_link_libraries(cpcd PRIVATE Threads::Threads cpc)
if(TARGET MbedTLS::mbedcrypto)
  target_link_libraries(cpcd PRIVATE MbedTLS::mbedcrypto)
endif()
if(TARGET backtrace)
  target_link_libraries(cpcd PRIVATE backtrace)
endif()

###

if(BUILD_TESTING AND (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME))
  message(STATUS "Enabling tests (${BUILD_TESTING})")
  add_subdirectory("./test")
endif()

###

install(TARGETS cpc
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(
  FILES "${PROJECT_BINARY_DIR}/libcpc.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

install(TARGETS cpcd
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "./cpcd.conf" DESTINATION "${CMAKE_INSTALL_FULL_SYSCONFDIR}")
