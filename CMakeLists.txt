cmake_minimum_required(VERSION 3.21)
project(chirouter_reference C)

# Default to a Debug build, but let -DCMAKE_BUILD_TYPE=... override it
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
# The code uses POSIX/GNU APIs (pthreads, getaddrinfo, NI_MAXHOST, ...)
# without feature-test macros, so it requires gnu17 rather than strict c17
set(CMAKE_C_EXTENSIONS ON)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_executable(chirouter
        src/c/arp.c
        src/c/ctx.c
        src/c/log.c
        src/c/main.c
        src/c/pcap.c
        src/c/router.c
        src/c/server.c
        src/c/utils.c)
target_include_directories(chirouter PRIVATE src/c)
target_compile_options(chirouter PRIVATE -Wall -Wextra -Wno-unused-parameter)
target_link_libraries(chirouter PRIVATE Threads::Threads)

set(TESTS_DIR ${PROJECT_SOURCE_DIR}/src/python/chirouter/tests)

add_custom_target(test-categories
        COMMAND ${TESTS_DIR}/print-categories.py ${TESTS_DIR}/rubric.json)
