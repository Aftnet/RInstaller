cmake_minimum_required (VERSION 3.20)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_COMPILE_WARNING_AS_ERROR OFF)

project(rinstaller)

add_subdirectory(deps)
add_subdirectory(common)
add_subdirectory(server)
add_subdirectory(client)
