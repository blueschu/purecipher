set(CMAKE_CXX_STANDARD 17)

# Register C++ wrapper library
file(GLOB purecipher_cpp_src src/*.c)
add_library(purecipher-cpp SHARED ${purecipher_cpp_src} src/pruecipher.cpp include/purecipher.hpp)
target_include_directories(purecipher-cpp PRIVATE ${CMAKE_SOURCE_DIR}/include ./include)

# Link wrapper against purecipher
add_dependencies(purecipher-cpp purecipher)
target_link_libraries(purecipher-cpp
        debug "${CMAKE_SOURCE_DIR}/target/debug/libpurecipher.so"
        optimized "${CMAKE_SOURCE_DIR}/target/release/libpurecipher.so")

# Add test executable
add_executable(purecipher-cpp-test test/test.cpp)
target_include_directories(purecipher-cpp-test PRIVATE ${CMAKE_SOURCE_DIR}/include ./include)
add_dependencies(purecipher-cpp-test purecipher-cpp)

# Link test exectuable against purecipher
target_link_libraries(purecipher-cpp-test purecipher-cpp
        debug "${CMAKE_SOURCE_DIR}/target/debug/libpurecipher.so"
        optimized "${CMAKE_SOURCE_DIR}/target/release/libpurecipher.so")
