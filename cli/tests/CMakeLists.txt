cmake_minimum_required(VERSION 3.6.0)

add_subdirectory(modules)

add_executable(clitests
    $<TARGET_OBJECTS:Modules>
    $<TARGET_OBJECTS:ModuleTests>)

target_link_libraries(clitests gtest gtest_main OpenPGP_shared)
set_target_properties(clitests PROPERTIES OUTPUT_NAME "tests")

add_test(NAME cli COMMAND cli/tests/tests WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
