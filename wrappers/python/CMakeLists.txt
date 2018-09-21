if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Build extension using cmake during development for better tooling integration
    set(CMAKE_C_STANDARD 11)
    # Get the path to the Python header files
    execute_process(
            COMMAND python3 -c "import sysconfig; print(sysconfig.get_path('include'))"
            OUTPUT_VARIABLE PYTHON_INCLUDE)
    message("Using Python headers from ${PYTHON_INCLUDE}")

    # Get the extension suffix for the python3 installation
    execute_process(
            COMMAND python3-config --extension-suffix
            COMMAND tr -d '\n'
            OUTPUT_VARIABLE PYTHON_EXTENSION_SUFFIX)

    # Get CFLAGS for building for the local python environment
    execute_process(
            COMMAND python3 -c "import sysconfig; print(sysconfig.get_config_var('CFLAGS'))"
            COMMAND tr -d '\n
            OUTPUT_VARIABLE PYTHON_CFLAGS)
    message("Using Python headers from ${PYTHON_INCLUDE}")

    file(GLOB purecipher_module_src purecipher/*.c)
    add_library(purecipher-python SHARED ${purecipher_module_src})
    set_target_properties(purecipher-python PROPERTIES
            PREFIX ""
            OUTPUT_NAME purecipher
            SUFFIX "${PYTHON_EXTENSION_SUFFIX}")

    target_include_directories(purecipher-python PRIVATE ${CMAKE_SOURCE_DIR}/include ${PYTHON_INCLUDE})
    target_link_libraries(purecipher-python "${CMAKE_SOURCE_DIR}/target/debug/libpurecipher.so")

    # Set compiler flags provide by Python.
    # I was unfortunetely unable to get target_compiler_options to interpret the flags
    # correctly, so the global CMAKE_C_FLAGS is set instead.
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}${PYTHON_CFLAGS}")
else ()
    # Build extension using setup.py for release
    add_custom_target(purecipher-python
            COMMENT "Building purecipher Python extension module"
            COMMAND python3 setup.py build
            WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})
endif ()

add_dependencies(purecipher-python purecipher)
