# purecipher

A rust library implementing pure (stateless) ciphers.

This repository is intended to serve as a terse demonstration of
inking a Python C extension with a rust library. 

## Testing
Each component of this repository includes (or will include) a set of
unit tests to verify their functionality. All tests can be run from 
the command line.

### Rust Tests
To build and run the Rust unit tests, simply use cargo's `test` command:
```bash
$ cargo test
```

### C Tests
Test cases for the C API exposed by the Rust crate may be found under the `ctest`
directory. These tests can be built and run via CMake:
```bash
$ mkdir -p ctest/cmake-build-debug
$ cd !$
$ cmake ..
$ make
$ ./ctest
```
If using CMake is not an option on your system, you may also compile the sources
by hand:
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