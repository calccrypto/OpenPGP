cmake_minimum_required(VERSION 3.6.0)

add_library(Tag17SubpacketTests OBJECT
    Sub1.cpp)

include_directories(Tag17SubpacketTests ${CMAKE_CURRENT_SOURCE_DIR}/..)
