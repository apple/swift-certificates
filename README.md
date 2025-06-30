# swift-certificates

A library for working with X.509 certificates.

## Overview

X.509 certificates are a commonly-used identity format to cryptographically
attest to the identity of an actor in a system. They form part of the X.509
standard created by the ITU-T for defining a public key infrastructure (PKI).
X.509-style PKIs are commonly used in cases where it is necessary to delegate
the authority to attest to an actor's identity to a small number of trusted
parties (called Certificate Authorities).

The most common usage of X.509 certificates today is as part of the WebPKI,
where they are used to secure TLS connections to websites. X.509 certificates
are also used in a wide range of other TLS-based communications, as well as
in code signing infrastructure.

This module makes it possible to serialize, deserialize, create, and interact
with X.509 certificates. This is an essential building-block for a wide range
of PKI applications. It enables building verifiers, interacting with
certificate authorities, authenticating peers, and more. It also ships with
a default verifier and a number of built-in verifier policies.

## Supported Swift Versions

This library will support the latest stable Swift version and the two versions prior.

## Getting Started

To use swift-certificates, add the following dependency to your Package.swift:

```swift
dependencies: [
    .package(url: "https://github.com/apple/swift-certificates.git", .upToNextMajor(from: "1.0.0"))
]
```

You can then add the specific product dependency to your target:

```swift
dependencies: [
    .product(name: "X509", package: "swift-certificates"),
]
```

For detailed usage and API documentation, check [the documentation](https://swiftpackageindex.com/apple/swift-certificates/documentation/x509).

## Benchmarks

Benchmarks for `swift-certificates` are in a separate Swift Package in the `Benchmarks` subfolder of this repository. 
They use the [`package-benchmark`](https://github.com/ordo-one/package-benchmark) plugin.
Benchmarks depends on the [`jemalloc`](https://jemalloc.net) memory allocation library, which is used by `package-benchmark` to capture memory allocation statistics.
An installation guide can be found in the [Getting Started article](https://swiftpackageindex.com/ordo-one/package-benchmark/documentation/benchmark/gettingstarted#Installing-Prerequisites-and-Platform-Support) of `package-benchmark`. 
Afterwards you can run the benchmarks from CLI by going to the `Benchmarks` subfolder (e.g. `cd Benchmarks`) and invoking:
```
swift package benchmark
```

For more information please refer to `swift package benchmark --help` or the [documentation of `package-benchmark`](https://swiftpackageindex.com/ordo-one/package-benchmark/documentation/benchmark). 

