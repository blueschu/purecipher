# C++ API to pureciphper

A C++ wrapper for the purecipher C API.

## Usage
To use this wrapper in a C++ project, simply include its header file in the
the relevant source files with `#include "purecipher.hpp"`. Do take note of the
`.hpp` extension given to this header to differentiate it from the purecipher
CAPI header, `purecipher.h`.

This wrapper is not implemented as a header-only library. In order to build a 
project that makes use of it, the library the is emitted for this wrapper must 
be discoverable at link time.

## Building
All commands are given relative to this repository's root, NOT relative to this 
file.

With CMake,
```bash
$ mkdir -p cmake-build-debug
$ cd !$
$ cmake  ..
$ make purecipher-cpp
```

## Testing
Unit tests for this library are provided by the CMake target `purecipher-cpp-test`.
If you have already built all CMake targets, these tests can run with
```bash
$ ./cmake-build-debug/wrappers/cplusplus/purecipher-cpp-test
```
where `cmake-build-debug` is the build directory used by CMake.

## Copyright & License
Copyright &copy; 2018 Brian Schubert - available under [MIT License][license].

[license]: ./LICENSE
