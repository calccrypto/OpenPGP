cmake_minimum_required(VERSION 3.2.0)

add_library(ModuleTests OBJECT
    fingerprint.cpp
    module.cpp)

target_include_directories(ModuleTests PUBLIC ${CMAKE_SOURCE_DIR})