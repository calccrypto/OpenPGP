cmake_minimum_required(VERSION 3.0.0)

add_library(common OBJECT
    includes.cpp)
    
set_property(TARGET common PROPERTY POSITION_INDEPENDENT_CODE ON)