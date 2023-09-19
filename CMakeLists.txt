cmake_minimum_required(VERSION 3.12)
project(libwebsocket)

set(CMAKE_CXX_STANDARD 11)

add_executable(${PROJECT_NAME}
    include/websocket.h
    include/certs.h
    include/sha1.h

    src/websocket.cpp
    src/example.cpp
    src/base64.c
    src/sha1.c
)

target_link_libraries(${PROJECT_NAME}
    pthread
    mbedtls
    mbedcrypto
    mbedx509
)

target_include_directories(${PROJECT_NAME} PRIVATE
    include
    /usr/local/include
)

target_link_directories(${PROJECT_NAME} PRIVATE
    /usr/lib
    /usr/local/lib
)