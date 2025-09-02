cmake_minimum_required(VERSION 3.16)
project(gdbsos-super)

# Ensure installed shared libraries (ELF .so) have the executable bit set, matching diagnostics
set(CMAKE_INSTALL_SO_NO_EXE OFF)

# Aggregate build entry for gdbsos components
add_subdirectory(gdbplugin)
