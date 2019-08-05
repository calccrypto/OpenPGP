cmake_minimum_required(VERSION 3.6.0)
project(OpenPGP LANGUAGES CXX)

# require C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# add extra warnings in debug mode
include(contrib/cmake/enable_cxx_compiler_flag_if_supported.cmake)
enable_cxx_compiler_flag_if_supported(CMAKE_CXX_FLAGS_DEBUG "-Wall")
enable_cxx_compiler_flag_if_supported(CMAKE_CXX_FLAGS_DEBUG "-Wextra")
enable_cxx_compiler_flag_if_supported(CMAKE_CXX_FLAGS_DEBUG "-pedantic")

# turns on code coverage (implies debug build)
set(CODE_COVERAGE OFF CACHE BOOL "Build with code coverage (implies debug build)")
if (CODE_COVERAGE)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} --coverage")
    set(CMAKE_BUILD_TYPE "Debug")
endif()

# GPG compatible mode
set(GPG_COMPATIBLE OFF CACHE BOOL "Build with GPG compatibility")
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
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/contrib/cmake)

# GNU Multiple Precision Arithmetic Library
find_package(GMP 5.0.0 REQUIRED)
message(STATUS "GMP headers:        ${GMP_INCLUDES}")
message(STATUS "GMP libraries:      ${GMP_LIBRARIES}")
include_directories(SYSTEM ${GMP_INCLUDES})
link_libraries     (${GMP_LIBRARIES} gmpxx)

# BZip2
find_package(BZip2 1.0.6 REQUIRED)
message(STATUS "BZip2 headers:      ${BZIP2_INCLUDE_DIR}")
message(STATUS "BZip2 libraries:    ${BZIP2_LIBRARIES}")
include_directories(SYSTEM ${BZIP2_INCLUDE_DIR})
link_libraries     (${BZIP2_LIBRARIES})

# zlib
find_package(ZLIB 1.2.8 REQUIRED)
message(STATUS "zlib headers:       ${ZLIB_INCLUDE_DIR}")
message(STATUS "zlib libraries:     ${ZLIB_LIBRARIES}")
include_directories(SYSTEM ${ZLIB_INCLUDE_DIR})
link_libraries     (${ZLIB_LIBRARIES})

# OpenSSL
set(USE_OPENSSL      OFF CACHE BOOL "Build with OpenSSL")
set(USE_OPENSSL_HASH OFF CACHE BOOL "Build with OpenSSL's Hash Algorithm Implementation.")
set(USE_OPENSSL_RNG  OFF CACHE BOOL "Build with OpenSSL's RNG")

if (USE_OPENSSL)
   set(USE_OPENSSL_HASH ON)
   set(USE_OPENSSL_RNG  ON)
endif()

if (USE_OPENSSL_HASH OR USE_OPENSSL_RNG)
    find_package(OpenSSL 1.1.0)
    if (OPENSSL_FOUND)
        message(STATUS "OpenSSL headers:    ${OPENSSL_INCLUDE_DIR}")
        message(STATUS "OpenSSL libraries:  ${OPENSSL_CRYPTO_LIBRARY}")
        include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})
        link_libraries     (${OPENSSL_CRYPTO_LIBRARY})
        if (USE_OPENSSL_HASH)
            message(STATUS "Using OpenSSL's hashing algorithms.")
            add_compile_options("-DOPENSSL_HASH")
        endif()
        if (USE_OPENSSL_RNG)
            message(STATUS "Using OpenSSL's RNG.")
            add_compile_options("-DOPENSSL_RNG")
        endif()
    else()
        if (USE_OPENSSL_HASH)
            message(STATUS "Could not find OpenSSL. Using unsafe custom hashing implementation.")
            set(USE_OPENSSL_HASH OFF)
        endif()
        if (USE_OPENSSL_RNG)
            message(STATUS "Could not find OpenSSL. Using unsafe custom RNG implementation.")
            set(USE_OPENSSL_RNG OFF)
        endif()
        set(USE_OPENSSL OFF)
    endif()
endif()

# -Iinclude
include_directories(include)

# add library directories
add_subdirectory(include)
add_subdirectory(src)

set(BUILD_STATIC_LIB ON CACHE BOOL "Build a static library")
if (BUILD_STATIC_LIB)
    # build the static library
    add_library(OpenPGP_static STATIC
        $<TARGET_OBJECTS:TopLevel>
        $<TARGET_OBJECTS:common>
        $<TARGET_OBJECTS:Compress>
        $<TARGET_OBJECTS:Encryptions>
        $<TARGET_OBJECTS:Hashes>
        $<TARGET_OBJECTS:HashAlgs>
        $<TARGET_OBJECTS:Misc>
        $<TARGET_OBJECTS:Packets>
        $<TARGET_OBJECTS:PKA>
        $<TARGET_OBJECTS:RNG>
        $<TARGET_OBJECTS:Tag2Subpackets>
        $<TARGET_OBJECTS:Tag17Subpackets>
    )
    set_target_properties(OpenPGP_static PROPERTIES OUTPUT_NAME "OpenPGP")
    install(TARGETS OpenPGP_static DESTINATION lib)
endif()

set(BUILD_SHARED_LIB ON CACHE BOOL "Build a shared library")
if (BUILD_SHARED_LIB)
    # build the shared library
    add_library(OpenPGP_shared SHARED
        $<TARGET_OBJECTS:TopLevel>
        $<TARGET_OBJECTS:common>
        $<TARGET_OBJECTS:Compress>
        $<TARGET_OBJECTS:Encryptions>
        $<TARGET_OBJECTS:Hashes>
        $<TARGET_OBJECTS:HashAlgs>
        $<TARGET_OBJECTS:Misc>
        $<TARGET_OBJECTS:Packets>
        $<TARGET_OBJECTS:PKA>
        $<TARGET_OBJECTS:RNG>
        $<TARGET_OBJECTS:Tag2Subpackets>
        $<TARGET_OBJECTS:Tag17Subpackets>
    )
    set_target_properties(OpenPGP_shared PROPERTIES OUTPUT_NAME "OpenPGP")
    install(TARGETS OpenPGP_shared DESTINATION lib)
endif()

set(BUILD_TESTS ON CACHE BOOL "Build tests")
if (BUILD_TESTS)
    # create the test target
    enable_testing()

    # add tests
    add_subdirectory(tests)
endif()


set(BUILD_CLI ON CACHE BOOL "Build CLI example")
if (BUILD_CLI)
    # add cli
    add_subdirectory(cli)
endif()

# add pkg-config
configure_file("contrib/OpenPGP.pc.in" "OpenPGP.pc" @ONLY)
install(FILES "${CMAKE_BINARY_DIR}/OpenPGP.pc" DESTINATION lib/pkgconfig)
