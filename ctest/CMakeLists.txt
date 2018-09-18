set(CMAKE_C_STANDARD 11)

add_executable(ctest test.c)
target_include_directories(ctest PRIVATE ../include)
add_dependencies(ctest purecipher)

target_link_libraries(ctest
        debug "${CMAKE_SOURCE_DIR}/target/debug/libpurecipher.so"
        optimized "${CMAKE_SOURCE_DIR}/target/release/libpurecipher.so")
