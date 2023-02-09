cmake_minimum_required(VERSION 3.10)
project(arftransfer)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# FreeBSD stuff
include_directories("/usr/local/include")
link_directories("/usr/local/lib")

# library
file (GLOB LIB_SRC
    "libarftransfer/*.cpp"
)

add_library(libarftransfer ${LIB_SRC})

# client
file (GLOB CLIENT_SRC
    "client/*.cpp"
)

add_executable(arftransfer ${CLIENT_SRC})

# server
file (GLOB SERVER_SRC
    "server/*.cpp"
)

add_executable(arftransferd ${SERVER_SRC})
target_link_libraries(arftransferd PRIVATE Threads::Threads)
