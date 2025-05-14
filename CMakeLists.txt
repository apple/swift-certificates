##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCertificates open source project
##
## Copyright (c) 2023 Apple Inc. and the SwiftCertificates project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

cmake_minimum_required(VERSION 3.19)

project(SwiftCertificates
  LANGUAGES Swift)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)

include(SwiftSupport)

option(BUILD_SHARED_LIBS "Build shared libraries by default" YES)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_Swift_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY MultiThreadedDLL)
set(CMAKE_Swift_MODULE_DIRECTORY ${CMAKE_BINARY_DIR}/swift)

set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreadedDLL)
set(CMAKE_POSITION_INDEPENDENT_CODE ${BUILD_SHARED_LIBS})

# Toolchain vended dependencies
find_package(dispatch CONFIG)
find_package(Foundation CONFIG)

include(FetchContent)

set(_CERT_SAVED_BUILD_EXAMPLES ${BUILD_EXAMPLES})
set(_CERT_SAVED_BUILD_TESTING ${BUILD_TESTING})

find_package(SwiftASN1 CONFIG)
if(NOT SwiftASN1_FOUND)
  message("-- Vending swift-asn1")
  FetchContent_Declare(ASN1
    GIT_REPOSITORY https://github.com/apple/swift-asn1
    GIT_TAG 1.1.0)
  FetchContent_MakeAvailable(ASN1)
endif()

find_package(SwiftCrypto CONFIG)
if(NOT SwiftCrypto_FOUND)
  message("-- Vending swift-crypto")
  FetchContent_Declare(Crypto
    GIT_REPOSITORY https://github.com/apple/swift-crypto
    GIT_TAG 3.2.0)
  FetchContent_MakeAvailable(Crypto)
endif()

set(BUILD_TESTING ${_CERT_SAVED_BUILD_TESTING})
set(BUILD_EXAMPLES ${_CERT_SAVED_BUILD_EXAMPLES})

add_subdirectory(Sources)
add_subdirectory(cmake/modules)

