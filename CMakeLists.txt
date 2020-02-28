cmake_minimum_required(VERSION 3.5.1)
project(chirouter_reference C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_BUILD_TYPE Debug)

include_directories(src lib/uthash/include)

add_executable(chirouter
        src/c/main.c
        src/c/server.c
        src/c/ctx.c
        src/c/log.c
        src/c/router.c
        src/c/arp.c
        src/c/utils.c
        src/c/pcap.c)

target_link_libraries(chirouter pthread)

