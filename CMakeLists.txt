cmake_minimum_required(VERSION 3.23)
project(asmaps)

set(CMAKE_CXX_STANDARD 14)
include_directories(meminfo/include)

add_library(smaps  meminfo/meminfo.cpp meminfo/stringprintf.cpp)

add_executable(${PROJECT_NAME} main.cpp)

target_link_libraries(${PROJECT_NAME} smaps)