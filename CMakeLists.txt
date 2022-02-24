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

add_custom_target(test-categories
        COMMAND ../src/python/chirouter/tests/print-categories.py ../src/python/chirouter/tests/rubric.json)

add_custom_target(tests
        COMMAND sudo pytest src/python/chirouter/tests/
        WORKING_DIRECTORY ../
        DEPENDS chirouter)

add_custom_target(grade
        COMMAND src/python/chirouter/tests/grade.py src/python/chirouter/tests/rubric.json
        WORKING_DIRECTORY ../)
