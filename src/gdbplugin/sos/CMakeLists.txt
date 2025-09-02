cmake_minimum_required(VERSION 3.16)
project(gdbsos-sos LANGUAGES NONE)

# Install the Python GDB plugin files (.py only) into the install directory root
install(DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/" DESTINATION . FILES_MATCHING PATTERN "*.py")
