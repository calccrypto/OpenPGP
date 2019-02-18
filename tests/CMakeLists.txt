cmake_minimum_required(VERSION 3.2.0)

set(INSTALL_GTEST OFF)

# Download and unpack googletest at configure time
configure_file(${CMAKE_SOURCE_DIR}/cmake/GoogleTest.txt.in googletest-download/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
if(result)
  message(FATAL_ERROR "CMake step for googletest failed: ${result}")
endif()
execute_process(COMMAND ${CMAKE_COMMAND} --build .
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
if(result)
  message(FATAL_ERROR "Build step for googletest failed: ${result}")
endif()

# Prevent overriding the parent project's compiler/linker
# settings on Windows
set(gtest_force_shared_cmariometroidrt ON CACHE BOOL "" FORCE)

# Add googletest directly to our build. This defines
# the gtest and gtest_main targets.
add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/googletest-src
                 ${CMAKE_CURRENT_BINARY_DIR}/googletest-build
                 EXCLUDE_FROM_ALL)

# The gtest/gtest_main targets carry header search path
# dependencies automatically when using CMake 2.8.11 or
# later. Otherwise we have to add them here ourselves.
# if (CMAKE_VERSION VERSION_LESS 2.8.11)
  include_directories("${gtest_SOURCE_DIR}/include")
# endif()

add_subdirectory(cli)
add_subdirectory(common)
add_subdirectory(Compress)
add_subdirectory(Encryptions)
add_subdirectory(Hashes)
add_subdirectory(Misc)
add_subdirectory(PKA)

add_library(TopLevelTests OBJECT
    gpg.cpp
    pgp.cpp)

file(COPY testvectors DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_executable(tests
    $<TARGET_OBJECTS:Modules>
    $<TARGET_OBJECTS:TopLevelTests>
    # $<TARGET_OBJECTS:CommonTests>
    $<TARGET_OBJECTS:CompressTests>
    $<TARGET_OBJECTS:EncryptionTests>
    # $<TARGET_OBJECTS:ExecTests>
    $<TARGET_OBJECTS:ModuleTests>
    $<TARGET_OBJECTS:HashTests>
    $<TARGET_OBJECTS:MiscTests>
    $<TARGET_OBJECTS:PKATests>)

target_link_libraries(tests gtest gtest_main OpenPGP_shared)

add_test(NAME tests COMMAND tests WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
