cmake_minimum_required(VERSION 3.22.1)
project(zygisk)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions -fno-rtti -fvisibility=hidden -fvisibility-inlines-hidden -flto=full -O3 -mllvm -polly")

include_directories(${CMAKE_SOURCE_DIR}/Dobby/include)

add_library(${PROJECT_NAME} SHARED ${CMAKE_SOURCE_DIR}/zygisk.cpp)

find_package(cxx REQUIRED CONFIG)
find_package(dobby REQUIRED CONFIG)

find_library(log-lib log)

target_link_libraries(${PROJECT_NAME} cxx::cxx dobby::dobby ${log-lib})