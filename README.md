# purecipher

A rust library implementing pure (stateless) ciphers.

This repository is intended to serve as a terse demonstration of
inking a Python C extension with a rust library. 

## Testing
Each component of this repository includes (or will include) a set of
unit tests that verify their functionality. All tests can be run from 
the command line.

### Rust Tests
To run build and run the Rust unit tests, simply use cargo's `test` command:
```bash
$ cargo test
```

## Acknowledgments
The layout of this repository was inspired by the C API for the [Rust Regex Engine][rure].

## Copyright & License
Copyright &copy; 2018 Brian Schubert - available under [MIT License][license].

[rure]: https://github.com/rust-lang/regex/tree/master/regex-capi
[license]: ./LICENSE