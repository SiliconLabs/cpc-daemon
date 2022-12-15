# 3.3: IN_LIST
# 3.5: Native cmake_parse_arguments
cmake_minimum_required(VERSION 3.5)

function(target_stds tgt)
  cmake_parse_arguments(ARG "" "C;CXX;POSIX" "" ${ARGN})
  # C standard
  if(DEFINED ARG_C)
    set_target_properties(${tgt} PROPERTIES
      C_STANDARD ${ARG_C}
      C_STANDARD_REQUIRED YES
      C_EXTENSIONS NO)
  endif()
  # C++ standard
  if(DEFINED ARG_CXX)
    set_target_properties(${tgt} PROPERTIES
      CXX_STANDARD ${ARG_CXX}
      CXX_STANDARD_REQUIRED YES
      CXX_EXTENSIONS NO)
  endif()
  # feature test macro for POSIX
  if(DEFINED ARG_POSIX)
    set(POSIX_VALUES "1990;1992;1993;1995;2001;2008")
    if(NOT ARG_POSIX IN_LIST POSIX_VALUES)
      message(FATAL_ERROR "POSIX standard \"${ARG_POSIX}\" not found in ${POSIX_VALUES}")
    endif()
    set(POSIX_VALUE_1990 "1")
    set(POSIX_VALUE_1992 "2")
    set(POSIX_VALUE_1993 "199309L") # real-time extensions
    set(POSIX_VALUE_1995 "199506L") # threads
    set(POSIX_VALUE_2001 "200112L")
    set(POSIX_VALUE_2008 "200809L")
    target_compile_definitions(${tgt} PRIVATE "_POSIX_C_SOURCE=${POSIX_VALUE_${ARG_POSIX}}")
  endif()
endfunction()
