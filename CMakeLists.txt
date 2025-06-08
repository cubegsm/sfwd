cmake_minimum_required(VERSION 3.16)
project(sfwd C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -DALLOW_EXPERIMENTAL_API")

find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

include_directories(${DPDK_INCLUDE_DIRS})
link_directories(${DPDK_LIBRARY_DIRS})
add_definitions(${DPDK_CFLAGS_OTHER})
include_directories(../common)

set(SOURCES
    main.c
    sfwd_acl.c
    sfwd_stat.c
    sfwd_rlimit.c
    log.c
)

add_executable(sfwd ${SOURCES})
target_link_libraries(sfwd ${DPDK_LIBRARIES})

