cmake_minimum_required(VERSION 3.6.0)

include_directories("${gtest_SOURCE_DIR}/include")

add_library(ModuleTests OBJECT
    fingerprint.cpp
    module.cpp)

target_include_directories(ModuleTests PUBLIC ${CMAKE_SOURCE_DIR})
