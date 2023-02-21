cmake_minimum_required(VERSION 3.10)
project(arftransfer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# FreeBSD stuff
include_directories("/usr/local/include")
link_directories("/usr/local/lib")

include_directories(".")

# library
file (GLOB LIB_SRC
    "libarftransfer/*.c"
)

add_library(objlib OBJECT ${LIB_SRC})
set_property(TARGET objlib PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library(arftransferstatic STATIC $<TARGET_OBJECTS:objlib>)
target_link_libraries(arftransferstatic PRIVATE z)
add_library(arftransfer SHARED $<TARGET_OBJECTS:objlib>)
target_link_libraries(arftransfer PRIVATE z)

# client
file (GLOB CLIENT_SRC
    "client/*.cpp"
)

add_executable(arftransferc ${CLIENT_SRC})
target_link_libraries(arftransferc PRIVATE Threads::Threads z arftransfer)

# server
file (GLOB SERVER_SRC
    "server/*.c"
    "server/*.cpp"
)

add_executable(arftransferd ${SERVER_SRC})
target_link_libraries(arftransferd PRIVATE Threads::Threads z arftransfer pam)
