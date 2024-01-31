# 3.7: VERSION_GREATER_EQUAL
cmake_minimum_required(VERSION 3.7)

include(FindPackageHandleStandardArgs)

if(DEFINED MbedTLS_FOUND)
  return()
endif()

if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.13")
  function(hex_to_dec HEX DEC_VAR)
    math(EXPR DEC "0x${HEX}" OUTPUT_FORMAT DECIMAL)
    set(${DEC_VAR} ${DEC} PARENT_SCOPE)
  endfunction()
else()
  function(hex_to_dec HEX DEC_VAR)
    string(REGEX MATCHALL "." HEX_LIST "${HEX}")
    foreach(HEX1 ${HEX_LIST})
      if(HEX1 MATCHES "[0-9]")
        set(DEC1 ${HEX1})
      elseif(HEX1 MATCHES "[Aa]")
        set(DEC1 10)
      elseif(HEX1 MATCHES "[Bb]")
        set(DEC1 11)
      elseif(HEX1 MATCHES "[Cc]")
        set(DEC1 12)
      elseif(HEX1 MATCHES "[Dd]")
        set(DEC1 13)
      elseif(HEX1 MATCHES "[Ee]")
        set(DEC1 14)
      elseif(HEX1 MATCHES "[Ff]")
        set(DEC1 15)
      else()
        message(FATAL_ERROR "Invalid format for hexidecimal character")
      endif()
      math(EXPR DEC "((${DEC}+0)*16)+${DEC1}")
    endforeach()
    set(${DEC_VAR} ${DEC} PARENT_SCOPE)
  endfunction()
endif()

find_path(MbedTLS_INCLUDE_DIR "mbedtls/version.h")
if(MbedTLS_INCLUDE_DIR)
  message(VERBOSE "Found MbedTLS version header in ${MbedTLS_INCLUDE_DIR}")
  file(STRINGS "${MbedTLS_INCLUDE_DIR}/mbedtls/version.h" MbedTLS_VERSION_NUMBER
    REGEX "MBEDTLS_VERSION_NUMBER")
  string(REGEX MATCH "0x([0-9A-F][0-9A-F])([0-9A-F][0-9A-F])([0-9A-F][0-9A-F])00$" MbedTLS_VERSION_NUMBER "${MbedTLS_VERSION_NUMBER}")
  hex_to_dec("${CMAKE_MATCH_1}" MbedTLS_VERSION_MAJOR)
  hex_to_dec("${CMAKE_MATCH_2}" MbedTLS_VERSION_MINOR)
  hex_to_dec("${CMAKE_MATCH_3}" MbedTLS_VERSION_PATCH)
  set(MbedTLS_VERSION "${MbedTLS_VERSION_MAJOR}.${MbedTLS_VERSION_MINOR}.${MbedTLS_VERSION_PATCH}")
endif()

if(NOT DEFINED MbedTLS_FIND_COMPONENTS)
  set(MbedTLS_FIND_COMPONENTS mbedtls)
endif()
foreach(c ${MbedTLS_FIND_COMPONENTS})
  find_library(MbedTLS_${c}_LIBRARY NAMES "mbed${c}")
  mark_as_advanced(MbedTLS_${c}_LIBRARY)
  if(MbedTLS_${c}_LIBRARY)
    message(VERBOSE "Found MbedTLS library ${c} at ${MbedTLS_${c}_LIBRARY}")
    set(MbedTLS_${c}_FOUND YES)
  endif()
endforeach()

# 3.19: HANDLE_VERSION_RANGE
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.19")
  find_package_handle_standard_args(MbedTLS
    REQUIRED_VARS MbedTLS_INCLUDE_DIR MbedTLS_VERSION
    VERSION_VAR MbedTLS_VERSION
    HANDLE_VERSION_RANGE
    HANDLE_COMPONENTS)
else()
  find_package_handle_standard_args(MbedTLS
    REQUIRED_VARS MbedTLS_INCLUDE_DIR MbedTLS_VERSION
    VERSION_VAR MbedTLS_VERSION
    HANDLE_COMPONENTS)
endif()

if(NOT MbedTLS_FOUND)
  return()
endif()

foreach(c ${MbedTLS_FIND_COMPONENTS})
  if(MbedTLS_${c}_FOUND)
    add_library(MbedTLS::mbed${c} UNKNOWN IMPORTED)
    set_target_properties(MbedTLS::mbed${c} PROPERTIES
      IMPORTED_LINK_INTERFACE_LANGUAGES "C"
      IMPORTED_LOCATION "${MbedTLS_${c}_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}")
  endif()
endforeach()
