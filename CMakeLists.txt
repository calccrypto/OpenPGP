cmake_minimum_required(VERSION 3.0.0)
project(OpenPGP LANGUAGES CXX)

# require C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# add extra warnings in debug mode
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -Wextra -g")

# GPG compatible mode
set(GPG_COMPATIBLE NO CACHE BOOL "Build with GPG compatibility")
if (GPG_COMPATIBLE)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DGPG_COMPATIBLE")
    set(CMAKE_CXX_FLAGS       "${CMAKE_CXX_FLAGS}       -DGPG_COMPATIBLE")
endif()

# ########################################################
# https://gitlab.kitware.com/cmake/community/wikis/doc/cmake/RPATH-handling
#
# use, i.e. don't skip the full RPATH for the build tree
SET(CMAKE_SKIP_BUILD_RPATH FALSE)

# when building, don't use the install RPATH already
# (but later on when installing)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

# add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# the RPATH to be used when installing, but only if it's not a system directory
LIST(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/lib" isSystemDir)
IF("${isSystemDir}" STREQUAL "-1")
   SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
ENDIF("${isSystemDir}" STREQUAL "-1")
# ########################################################

# GMP is not a built-in module, so it needs FindGMP.cmake to be available
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)

# GNU Multiple Precision Arithmetic Library
find_package(GMP 5.0.0 REQUIRED)
message(STATUS "GMP headers:     ${GMP_INCLUDES}")
message(STATUS "GMP libraries:   ${GMP_LIBRARIES}")
include_directories(${GMP_INCLUDES})
link_libraries     (${GMP_LIBRARIES} gmpxx)

# BZip2
find_package(BZip2 1.0.6 REQUIRED)
message(STATUS "BZip2 headers:   ${BZIP2_INCLUDE_DIR}")
message(STATUS "BZip2 libraries: ${BZIP2_LIBRARIES}")
include_directories(${BZIP2_INCLUDE_DIR})
link_libraries     (${BZIP2_LIBRARIES})

# zlib
find_package(ZLIB 1.2.8 REQUIRED)
message(STATUS "zlib headers:    ${ZLIB_INCLUDE_DIR}")
message(STATUS "zlib libraries:  ${ZLIB_LIBRARIES}")
include_directories(${ZLIB_INCLUDE_DIR})
link_libraries     (${ZLIB_LIBRARIES})

include_directories(include)

enable_testing()

add_subdirectory(include)
add_subdirectory(src)
add_subdirectory(tests)

add_library(OpenPGP_static STATIC
    $<TARGET_OBJECTS:TopLevel>
    $<TARGET_OBJECTS:common>
    $<TARGET_OBJECTS:Compress>
    $<TARGET_OBJECTS:Encryptions>
    $<TARGET_OBJECTS:Hashes>
    $<TARGET_OBJECTS:Misc>
    $<TARGET_OBJECTS:Packets>
    $<TARGET_OBJECTS:PKA>
    $<TARGET_OBJECTS:RNG>
    $<TARGET_OBJECTS:Subpackets>
    $<TARGET_OBJECTS:Tag2Subpackets>
    $<TARGET_OBJECTS:Tag17Subpackets>
)
set_target_properties(OpenPGP_static PROPERTIES OUTPUT_NAME "OpenPGP")
install(TARGETS OpenPGP_static DESTINATION lib)

add_library(OpenPGP_shared SHARED
    $<TARGET_OBJECTS:TopLevel>
    $<TARGET_OBJECTS:common>
    $<TARGET_OBJECTS:Compress>
    $<TARGET_OBJECTS:Encryptions>
    $<TARGET_OBJECTS:Hashes>
    $<TARGET_OBJECTS:Misc>
    $<TARGET_OBJECTS:Packets>
    $<TARGET_OBJECTS:PKA>
    $<TARGET_OBJECTS:RNG>
    $<TARGET_OBJECTS:Subpackets>
    $<TARGET_OBJECTS:Tag2Subpackets>
    $<TARGET_OBJECTS:Tag17Subpackets>
)
set_target_properties(OpenPGP_shared PROPERTIES OUTPUT_NAME "OpenPGP")
install(TARGETS OpenPGP_shared DESTINATION lib)