# Inspired by Meson's warning_level option

if(NOT DEFINED WARNING_LEVEL)
  set(WARNING_LEVEL 2)
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
      -Wformat=2
      -Wlogical-op
      -Wmissing-declarations
      -Wpointer-arith
      -Wsign-conversion
      -Wswitch-default
    )
  endif()

  include(CheckCCompilerFlag)
  foreach(_WARNING IN LISTS _POSSIBLE_WARNINGS)
    string(MAKE_C_IDENTIFIER ${_WARNING} _warning)
    check_c_compiler_flag(${_WARNING} ${_warning})
    if(${_warning})
      add_compile_options(${_WARNING})
    endif()
  endforeach()
  unset(_POSSIBLE_WARNINGS)
endif()

if(CMAKE_VERSION VERSION_LESS "3.24")
  if(CMAKE_COMPILE_WARNING_AS_ERROR)
    message(STATUS "Treating compile warnings as errors")
    add_compile_options(-Werror)
  endif()
endif()
