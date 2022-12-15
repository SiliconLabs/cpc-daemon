# Inspired by Meson's warning_level option

add_library(_Warnings INTERFACE)
add_library(Interface::Warnings ALIAS _Warnings)

if(NOT DEFINED WARNING_LEVEL)
  if(NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(WARNING_LEVEL 2)
  endif()
endif()

if(WARNING_LEVEL GREATER_EQUAL "1")
  list(APPEND _POSSIBLE_WARNINGS -Wall)
  if(WARNING_LEVEL GREATER_EQUAL "2")
    list(APPEND _POSSIBLE_WARNINGS -Wextra)
    if(WARNING_LEVEL GREATER_EQUAL "3")
      list(APPEND _POSSIBLE_WARNINGS -Wpedantic)
    endif()

    # Custom warnings
    list(APPEND _POSSIBLE_WARNINGS
      -Wconversion
      -Wmissing-declarations
      -Wsign-conversion
      -Wswitch-default
    )
  endif()

  include(CheckCCompilerFlag)
  foreach(_WARNING IN LISTS _POSSIBLE_WARNINGS)
    string(MAKE_C_IDENTIFIER "${_WARNING}" _warning)
    check_c_compiler_flag(${_WARNING} ${_warning})
    if(${_warning})
      target_compile_options(_Warnings INTERFACE "${_WARNING}")
    endif()
  endforeach()
  unset(_POSSIBLE_WARNINGS)
endif()
