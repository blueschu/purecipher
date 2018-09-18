cmake_minimum_required(VERSION 3.10.2)
project(purecipher)

# Rust Library

# Optimization levels for Rust builds
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CARGO_CMD cargo build)
else ()
    set(CARGO_CMD cargo build --release)
endif ()

# Compile Rust library
add_custom_target(purecipher
        COMMENT "Compiling purecipher crate"
        COMMAND ${CARGO_CMD} --manifest-path ${CMAKE_SOURCE_DIR}/Cargo.toml)

# C Tests against Rust FFI
add_subdirectory(ctest)
add_subdirectory(wrappers/python)
