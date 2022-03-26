cmake_minimum_required(VERSION 3.20.1)
project(ws-https-proxy)
include(ExternalProject)

set(CMAKE_C_STANDARD 11)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

ExternalProject_Add(libuv_project
        SOURCE_DIR        ${CMAKE_SOURCE_DIR}/deps/libuv
        CONFIGURE_COMMAND cd <SOURCE_DIR> && mkdir -p build
        COMMAND           cd <SOURCE_DIR> && cd build/ && cmake ..
        BUILD_COMMAND     cd <SOURCE_DIR> && cd build/ && make -j8
        INSTALL_COMMAND   ""
        TEST_COMMAND      ""
)

ExternalProject_Add(picohttpparser_project
        SOURCE_DIR        ${CMAKE_SOURCE_DIR}/deps/picohttpparser
        CONFIGURE_COMMAND ""
        COMMAND           ""
        BUILD_COMMAND     cd <SOURCE_DIR> && make -j1
        INSTALL_COMMAND   ""
        TEST_COMMAND      ""
)

link_directories(deps/libuv/build)
include_directories(deps/libuv/include)
include_directories(deps/picohttpparser)

set(DEBUG_FLAGS "-DDEBUG -Og -Wall -Wpedantic -pedantic -march=native")
set(OPTIMIZE_FLAGS "-O3 -ffast-math -ftree-vectorize -funroll-loops -Wall -Wpedantic -pedantic -march=native -flto -fwrapv -fomit-frame-pointer")
set(SANITIZER_FLAGS -fsanitize=address -fno-omit-frame-pointer)
set(GCC_HELPER_FLAGS -fvar-tracking-assignments)
set(LINK_FLAGS "-lm -lpthread -lrt -lssl -lcrypto -luv")


set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${DEBUG_FLAGS}")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${OPTIMIZE_FLAGS}")



set(SRC evt_tls.c sha1.c tls.c uv_tls.c ws_proxy.c wsparser.c deps/picohttpparser/picohttpparser.c)
add_executable(main ${SRC})
target_link_libraries(main ${LINK_FLAGS})
add_dependencies(main libuv_project picohttpparser_project)
