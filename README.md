# Aedile

A Nostr System Development Kit written in C++.

## Behind the Name

In the ancient Roman Republic, the aediles were officials elected from among the plebians and charged with caring for Rome's public infrastructure and ensuring an accurate system of weights and measures.

The aim of the Aedile SDK is in the spirit of that ancient office:

- Provide a fast and efficient service for interacting with Nostr relays via WebSocket connections.
- Offer stable, well-tested implementations of commonly-used [Nostr Implementation Possibilities (NIPs)](https://github.com/nostr-protocol/nips/tree/master).
- Open up Nostr development by taking care of the basics so developers can focus on solving problems, rather than reimplementing the protocol.

## Building the SDK

### Prerequisites

This project uses CMake as its build system, and vcpkg as its dependency manager.  Thus, to build the SDK, you will need the following:

- CMake 3.19 or later
- A C++17 compiler
- vcpkg

CMake invokes vcpkg at the start of the configure process to install some of the project's dependencies.  For this step to succeed, ensure that the `VCPKG_ROOT` environment variable is set to the path of your vcpkg installation.

We have included vcpkg as a git submodule that needs to initialized and updated. The `VCPKG_ROOT` is already
set within the `CMakePresets.json` file, so all that needs to be done is simply initializing the submodule
and building the code.

```bash
cd aedile-ndk
git submodule init
git submodule update
```

### Building and Testing

The SDK aims to support Linux, Windows, and macOS build targets.  It currently supplies a CMake preset for Linux.

#### Linux

To build the SDK on Linux, run the following commands from the project root:

```bash
cmake --build --preset="linux"
```

To run unit tests, use the following commands:

```bash
cmake --build --preset="linux tests"
ctest --preset="linux"
```
