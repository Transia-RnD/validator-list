# validator-list

XRP Ledger validator list generation tool

## Table of contents

* [Dependencies](#dependencies)
  * [ripple-libpp submodule](#ripple-libpp-submodule)
  * [Other dependencies](#other-dependencies)
* [Build and run](#build-and-run)
* [Guide](#guide)

## Dependencies

### ripple-libpp submodule

This includes a git submodule to the ripple-libpp source code, which is not cloned by default. To get the ripple-libpp source, either clone this repository using
```
$ git clone --recursive <location>
```
or after cloning, run the following commands
```
$ git submodule update --init --recursive
```

### Other dependencies

* C++14 or greater
* [Boost](http://www.boost.org/)
* [OpenSSL](https://www.openssl.org/)
* [cmake](https://cmake.org)

## Build and run

For linux and other unix-like OSes, run the following commands:

```
$ cd ${YOUR_VALIDATOR_KEYS_TOOL_DIRECTORY}
$ mkdir -p build/gcc.debug
$ cd build/gcc.debug
$ cmake ../..
$ cmake --build .
$ ./validator-lists
```

For 64-bit Windows, open a MSBuild Command Prompt for Visual Studio
and run the following commands:

```
> cd %YOUR_VALIDATOR_KEYS_TOOL_DIRECTORY%
> mkdir build
> cd build
> cmake -G"Visual Studio 14 2015 Win64" ..
> cmake --build .
> .\Debug\validator-lsit.exe
```

32-bit Windows builds are not officially supported.

## Guide

[Validator List Guide](doc/validator-list-guide.md)
