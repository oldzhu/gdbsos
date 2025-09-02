cmake_minimum_required(VERSION 3.16)
project(sosgdbbridge LANGUAGES CXX)

# Configuration
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
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

# Include paths required by extensions.h and corhdr.h
include_directories(
  "${DIAGNOSTICS_SRC}/shared/inc"      # for corhdr.h
  "${DIAGNOSTICS_SRC}/shared/minipal"  # minipal public headers
  "${DIAGNOSTICS_SRC}/shared/pal/inc"  # PAL headers
  "${DIAGNOSTICS_SRC}/shared/pal/inc/rt"  # PAL runtime headers (unknwn.h)
  "${DIAGNOSTICS_SRC}/shared/pal/prebuilt/inc" # PAL prebuilt SDK headers
  "${DIAGNOSTICS_SRC}/shared/native"   # for minipal/utils.h
  "${DIAGNOSTICS_SRC}/SOS/inc"         # for host/debugger/symbol headers
  "${DIAGNOSTICS_SRC}/SOS/extensions"  # extension public headers
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
# Match diagnostics' native flags where RTTI is disabled for these components
target_compile_options(sosgdbbridge PRIVATE -Wno-delete-non-virtual-dtor -Wno-pragma-pack -fno-rtti)

# Mirror diagnostics target-arch/OS defines so PAL headers pick correct layout
if(UNIX)
  # Needed for __declspec(uuid()), MIDL_INTERFACE and friends on non-MSVC compilers
  target_compile_options(sosgdbbridge PRIVATE -fms-extensions -fvisibility=default)
  target_compile_definitions(sosgdbbridge PRIVATE _MIDL_USE_GUIDDEF_)
  # Prefer Clang for MS extensions; GCC lacks full support for __declspec(uuid)
  if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    message(WARNING "Building with GCC may fail on __declspec(uuid). Consider using Clang: set CC=clang CXX=clang++.")
  endif()
  target_compile_definitions(sosgdbbridge PRIVATE TARGET_UNIX)
endif()

string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _proc)
if(_proc STREQUAL "x86_64" OR _proc STREQUAL "amd64")
  target_compile_definitions(sosgdbbridge PRIVATE TARGET_64BIT TARGET_AMD64 HOST_AMD64 UNIX_AMD64_ABI)
elseif(_proc STREQUAL "aarch64" OR _proc STREQUAL "arm64")
  target_compile_definitions(sosgdbbridge PRIVATE TARGET_64BIT TARGET_ARM64 HOST_ARM64)
elseif(_proc MATCHES "^(armv7l|arm|armhf)$")
  target_compile_definitions(sosgdbbridge PRIVATE TARGET_ARM HOST_ARM)
elseif(_proc STREQUAL "i386" OR _proc STREQUAL "i686" OR _proc STREQUAL "x86")
  target_compile_definitions(sosgdbbridge PRIVATE TARGET_X86 HOST_X86 UNIX_X86_ABI)
endif()

target_include_directories(sosgdbbridge PRIVATE
  "${DIAGNOSTICS_SRC}/shared/inc"
  "${DIAGNOSTICS_SRC}/shared/minipal"
  "${DIAGNOSTICS_SRC}/shared/pal/inc"
  "${DIAGNOSTICS_SRC}/shared/pal/inc/rt"
  "${DIAGNOSTICS_SRC}/shared/pal/prebuilt/inc"
  "${DIAGNOSTICS_SRC}/shared/native"
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

# Create split debug symbols (libsosgdbbridge.so.dbg) for non-Debug builds, like diagnostics
if (UNIX AND NOT APPLE)
  find_program(OBJCOPY_TOOL objcopy)
  find_program(STRIP_TOOL strip)
  if (OBJCOPY_TOOL AND STRIP_TOOL)
    if (CMAKE_BUILD_TYPE MATCHES "^(RelWithDebInfo|Release|MinSizeRel)$")
      add_custom_command(TARGET sosgdbbridge POST_BUILD
        COMMAND "${OBJCOPY_TOOL}" --only-keep-debug "$<TARGET_FILE:sosgdbbridge>" "$<TARGET_FILE_DIR:sosgdbbridge>/$<TARGET_FILE_NAME:sosgdbbridge>.dbg"
        COMMAND "${STRIP_TOOL}" --strip-debug --strip-unneeded "$<TARGET_FILE:sosgdbbridge>"
  # Do not quote the generator expression with --add-gnu-debuglink to avoid escaped quotes being passed to objcopy
  COMMAND "${OBJCOPY_TOOL}" --add-gnu-debuglink=$<TARGET_FILE_DIR:sosgdbbridge>/$<TARGET_FILE_NAME:sosgdbbridge>.dbg "$<TARGET_FILE:sosgdbbridge>"
        COMMENT "Generating split debug symbols: $<TARGET_FILE_NAME:sosgdbbridge>.dbg"
        VERBATIM)
      # Install the .dbg file next to the shared library
      install(FILES "$<TARGET_FILE_DIR:sosgdbbridge>/$<TARGET_FILE_NAME:sosgdbbridge>.dbg" DESTINATION .)
    endif()
  endif()
endif()

# Optional: also deploy the built bridge next to diagnostics' libsos.so for testing
option(BRIDGE_DEPLOY_TO_DIAGNOSTICS "Copy libsosgdbbridge.so to diagnostics artifacts/bin after build" OFF)
set(BRIDGE_DEPLOY_DIAG_DIR "" CACHE PATH "Explicit diagnostics bin directory (e.g., <diagnostics>/artifacts/bin/linux.x64.Release or .../current)")

if (BRIDGE_DEPLOY_TO_DIAGNOSTICS)
  set(_deploy_dir "${BRIDGE_DEPLOY_DIAG_DIR}")
  if (NOT _deploy_dir)
    # Derive from DIAGNOSTICS_ROOT and current build type/arch if not provided
    string(TOLOWER "${CMAKE_SYSTEM_NAME}" _os)
    if (_os STREQUAL "linux")
      set(_os linux)
    endif()
    set(_arch "${CMAKE_SYSTEM_PROCESSOR}")
    if(_arch STREQUAL "x86_64")
      set(_arch x64)
    elseif(_arch STREQUAL "aarch64")
      set(_arch arm64)
    elseif(_arch MATCHES "^(armv7l|arm|armhf)$")
      set(_arch arm)
    endif()
    if (DIAGNOSTICS_ROOT)
      set(_deploy_dir "${DIAGNOSTICS_ROOT}/artifacts/bin/${_os}.${_arch}.${CMAKE_BUILD_TYPE}")
    endif()
  endif()
  if (_deploy_dir)
    file(MAKE_DIRECTORY "${_deploy_dir}")
    add_custom_command(TARGET sosgdbbridge POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:sosgdbbridge>" "${_deploy_dir}/"
      COMMENT "Deploying libsosgdbbridge.so to ${_deploy_dir}")

    # In non-Debug builds, also deploy the split debug file next to the .so
    if (CMAKE_BUILD_TYPE MATCHES "^(RelWithDebInfo|Release|MinSizeRel)$")
      add_custom_command(TARGET sosgdbbridge POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE_DIR:sosgdbbridge>/$<TARGET_FILE_NAME:sosgdbbridge>.dbg" "${_deploy_dir}/"
        COMMENT "Deploying libsosgdbbridge.so.dbg to ${_deploy_dir}")
    endif()

    # Additionally, if diagnostics 'current' directory exists, copy there too using a CMake helper script
    add_custom_command(TARGET sosgdbbridge POST_BUILD
      COMMAND ${CMAKE_COMMAND} -D CURRENT_DIR="${DIAGNOSTICS_ROOT}/artifacts/bin/current" -D SRC_SO="$<TARGET_FILE:sosgdbbridge>" -P "${CMAKE_CURRENT_LIST_DIR}/cmake/DeployToCurrent.cmake"
      COMMENT "Deploying libsosgdbbridge.so to diagnostics 'current' if present")
    if (CMAKE_BUILD_TYPE MATCHES "^(RelWithDebInfo|Release|MinSizeRel)$")
      add_custom_command(TARGET sosgdbbridge POST_BUILD
        COMMAND ${CMAKE_COMMAND} -D CURRENT_DIR="${DIAGNOSTICS_ROOT}/artifacts/bin/current" -D SRC_DBG="$<TARGET_FILE_DIR:sosgdbbridge>/$<TARGET_FILE_NAME:sosgdbbridge>.dbg" -P "${CMAKE_CURRENT_LIST_DIR}/cmake/DeployToCurrent.cmake"
        COMMENT "Deploying libsosgdbbridge.so.dbg to diagnostics 'current' if present")
    endif()

    # Also copy the Python plugin files (.py) into diagnostics bin and 'current' to co-locate everything
    file(GLOB _PY_FILES "${CMAKE_CURRENT_LIST_DIR}/../sos/*.py")
    if(_PY_FILES)
      add_custom_command(TARGET sosgdbbridge POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${_PY_FILES} "${_deploy_dir}/"
        COMMENT "Deploying Python sos plugin files to ${_deploy_dir}")
      add_custom_command(TARGET sosgdbbridge POST_BUILD
        COMMAND ${CMAKE_COMMAND} -D CURRENT_DIR="${DIAGNOSTICS_ROOT}/artifacts/bin/current" -D SRC_PYS="${_PY_FILES}" -P "${CMAKE_CURRENT_LIST_DIR}/cmake/DeployToCurrent.cmake"
        COMMENT "Deploying Python sos plugin files to diagnostics 'current' if present")
    endif()
  else()
    message(WARNING "BRIDGE_DEPLOY_TO_DIAGNOSTICS is ON but no deploy dir resolved; set -DBRIDGE_DEPLOY_DIAG_DIR or -DDIAGNOSTICS_ROOT")
  endif()
endif()

