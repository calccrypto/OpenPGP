cmake_minimum_required(VERSION 3.6.0)

add_executable(cli main.cpp $<TARGET_OBJECTS:Modules>)
target_link_libraries(cli OpenPGP_shared)
install(TARGETS cli DESTINATION bin)
set_target_properties(cli PROPERTIES OUTPUT_NAME "OpenPGP")

add_subdirectory(modules)
add_subdirectory(tests)
