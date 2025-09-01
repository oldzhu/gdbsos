project(sosgdbbridge)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_compile_options(-Wno-delete-non-virtual-dtor)

include_directories(${ROOT_DIR}/src/SOS/inc)
include_directories(${ROOT_DIR}/src/SOS/extensions)

set(SOURCES
    gdbbridge.cpp
)

add_library_clr(sosgdbbridge SHARED ${SOURCES})
target_link_libraries(sosgdbbridge extensions)

install_clr(TARGETS sosgdbbridge DESTINATIONS .)
