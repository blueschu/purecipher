cmake_minimum_required(VERSION 3.10.2)
project(purecipher-ctest)

set(CMAKE_C_STANDARD 11)

add_executable(ctest test.c)
target_include_directories(ctest PRIVATE ../include)

# Optimization levels for Rust builds
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CARGO_CMD cargo build)
else ()
    set(CARGO_CMD cargo build --release)
endif ()

# Compile Rust library
add_custom_target(purecipher
        COMMENT "Compiling purecipher crate"
        COMMAND ${CARGO_CMD} --manifest-path ${CMAKE_SOURCE_DIR}/../Cargo.toml
)

add_dependencies(ctest purecipher)

target_link_libraries(ctest
        debug "${CMAKE_SOURCE_DIR}/../target/debug/libpurecipher.so"
        optimized "${CMAKE_SOURCE_DIR}/../target/release/libpurecipher.so")
