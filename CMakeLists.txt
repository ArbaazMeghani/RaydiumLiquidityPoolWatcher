cmake_minimum_required(VERSION 3.14)
project(RaydiumPoolWatcher CXX)

# Enable C++20 standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include FetchContent module
include(FetchContent)

# Fetch websocketpp
FetchContent_Declare(
    websocketpp
    GIT_REPOSITORY https://github.com/zaphoyd/websocketpp.git
    GIT_TAG develop
)

# Fetch standalone ASIO (instead of full Boost)
FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG asio-1-18-1
)

# Make available
FetchContent_MakeAvailable(websocketpp asio)

# Add the source file
add_executable(watcher watcher.cpp)

# Include directories for websocketpp and standalone ASIO
target_include_directories(watcher PRIVATE
    ${websocketpp_SOURCE_DIR}
    ${asio_SOURCE_DIR}/asio/include
    ${threads_SOURCE_DIR}
)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
target_link_libraries(watcher PRIVATE Threads::Threads OpenSSL::SSL OpenSSL::Crypto)