cmake_minimum_required(VERSION 3.16)
project(sosgdbbridge LANGUAGES CXX)

# Configuration
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Inputs
set(DIAGNOSTICS_ROOT "${DIAGNOSTICS_ROOT}" CACHE PATH "Path to diagnostics repo root")
set(DIAGNOSTICS_SRC  "${DIAGNOSTICS_SRC}"  CACHE PATH "Path to diagnostics/src")

if(NOT DIAGNOSTICS_SRC AND DIAGNOSTICS_ROOT)
  set(DIAGNOSTICS_SRC "${DIAGNOSTICS_ROOT}/src")
endif()

if(NOT EXISTS "${DIAGNOSTICS_SRC}/SOS")
  message(FATAL_ERROR "DIAGNOSTICS_SRC not set or invalid. Pass -DDIAGNOSTICS_SRC=<path to diagnostics>/src")
endif()

# Include paths (mirrors the old ROOT_DIR includes)
include_directories(
  "${DIAGNOSTICS_SRC}/SOS/inc"
  "${DIAGNOSTICS_SRC}/SOS/extensions"
)

# Locate the prebuilt 'extensions' library from diagnostics
# You can override via -DEXTENSIONS_LIB=/path/to/libextensions.a
set(EXTENSIONS_LIB "" CACHE FILEPATH "Path to diagnostics libextensions")
if(NOT EXTENSIONS_LIB)
  # Try common diagnostics output locations
  string(TOLOWER "${CMAKE_SYSTEM_NAME}" _os)
  if(_os STREQUAL "linux")
    set(_os linux)
  endif()

  # Map archs similar to build.sh for hints
  set(_arch "${CMAKE_SYSTEM_PROCESSOR}")
  if(_arch STREQUAL "x86_64")
    set(_arch x64)
  elseif(_arch STREQUAL "aarch64")
    set(_arch arm64)
  elseif(_arch STREQUAL "armv7l")
    set(_arch arm)
  endif()

  foreach(dir
    "${DIAGNOSTICS_ROOT}/artifacts/obj/${_os}.${_arch}.${CMAKE_BUILD_TYPE}/SOS/extensions"
    "${DIAGNOSTICS_ROOT}/artifacts/obj/${_os}.${_arch}.${CMAKE_BUILD_TYPE}"
    "${DIAGNOSTICS_ROOT}/artifacts/bin/${_os}.${_arch}.${CMAKE_BUILD_TYPE}/SOS/extensions"
    "${DIAGNOSTICS_ROOT}/artifacts/bin/${_os}.${_arch}.${CMAKE_BUILD_TYPE}"
  )
    if(NOT EXTENSIONS_LIB)
      find_library(EXTENSIONS_LIB NAMES extensions libextensions.a HINTS "${dir}")
    endif()
  endforeach()
endif()

if(NOT EXTENSIONS_LIB)
  message(FATAL_ERROR "Could not find diagnostics 'extensions' library. Pass -DEXTENSIONS_LIB=/path/to/libextensions.a")
endif()

# Sources
set(SOURCES
  gdbbridge.cpp
)

# Library
add_library(sosgdbbridge SHARED ${SOURCES})
target_compile_options(sosgdbbridge PRIVATE -Wno-delete-non-virtual-dtor)

target_include_directories(sosgdbbridge PRIVATE
  "${DIAGNOSTICS_SRC}/SOS/inc"
  "${DIAGNOSTICS_SRC}/SOS/extensions"
)

target_link_libraries(sosgdbbridge PRIVATE
  "${EXTENSIONS_LIB}"
  dl
  pthread
)

# Install to CMAKE_INSTALL_PREFIX (build.sh sets it to artifacts/bin/linux.<arch>.<cfg>/SOS)
install(TARGETS sosgdbbridge
  LIBRARY DESTINATION .
  RUNTIME DESTINATION .
  ARCHIVE DESTINATION .
)
