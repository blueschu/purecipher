# purecipher

A rust library implementing pure (stateless) ciphers.

This repository is intended to serve as a terse demonstration of interfacing
with Rust libraries over a foreign functions interface. None of the libraries 
included within this repository are intended for practical applications. What I
have coined as "pure ciphers" are simply trivial substitution ciphers with 
negligible cryptographic value. The APIs of the libraries in the repository are,
by design, left wanting of many features.

## Usage
To incorporate the latest version of the purecipher library in a Rust crate, 
add the following to the dependencies section of your `Cargo.toml` configuration:
```toml
[dependencies]
purecipher = { git = "https://github.com/blueschu/purecipher" }
```

Since the purecipher library is designed to demonstrate the implementation of
foreign function interfaces, it of courses exposes a C API. This interface is 
described by the C header file `./include/purecipher.h`. To use purecipher in a 
C project, simply `#include` this header file and ensure that the purecipher 
library file is discoverable at link time. To use the purecipher library in a 
non-C, non-Rust environment, you may either employ a language specific FFI 
library or make use of one the wrapper libraries provided in the `./wrappers` 
of this repository. Usage instructions for each of these wrappers are 
documented in the `README.md` files  found in their respective source roots.

## Building
All components of this repository can be built using CMake for convenience. To 
build all CMake targets, you may run the following.
```bash
$ mkdir -p cmake-build-debug
$ cd !$
$ cmake ..
$ make
```
Specific targets, (e.g. `purecipher` or `ctest`) may follow the `make` command 
above to build only those targets. For a full listing of applicable targets, see
the `CMakeList.txt` files located throughout this repository. 

System dependencies for targets are documented in the `README` files located in 
their respective source root.

## Testing
Each component of this repository includes a set of unit tests. The procedure
for running these tests varies between components. Testing procedures for the
main rust library are documented below. For running unit tests against wrapper
implementations, see the `README` files in their source directory.

### Rust Tests
To build and run the Rust unit tests, simply use cargo's `test` command:
```bash
$ cargo test
```

### C Tests
Test cases for the C API exposed by the Rust crate may be found under the `ctest`
directory. If you have already built all CMake targets, these tests can run with
```bash
$ ./cmake-build-debug/ctest/ctest
```
where `cmake-build-debug` is the build directory used by CMake.

If using CMake is not an option on your system, you may also compile the test 
sources by hand:
```bash
$ cd ctest
$ cargo build --manifest-path ../Cargo.toml
$ cc -o ctest test.c --std=c11 -Wall -I../include -L../target/debug -lpurecipher
$ LD_LIBRARY_PATH=../target/debug ./ctest
```
where `cc` is a compatible C compiler of your choosing (e.g. `gcc`, `clang`).

## Acknowledgments
The layout of this repository was inspired by the C API for the [Rust Regex Engine][rure].

## Copyright & License
Copyright &copy; 2018 Brian Schubert - available under [MIT License][license].

[rure]: https://github.com/rust-lang/regex/tree/master/regex-capi
[license]: ./LICENSE
