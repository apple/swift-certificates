##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftASN1 open source project
##
## Copyright (c) 2023 Apple Inc. and the SwiftASN1 project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftASN1 project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

add_library(SwiftASN1
  "ASN1.swift"
  "Basic ASN1 Types/ASN1Any.swift"
  "Basic ASN1 Types/ASN1BitString.swift"
  "Basic ASN1 Types/ASN1Boolean.swift"
  "Basic ASN1 Types/ASN1Identifier.swift"
  "Basic ASN1 Types/ASN1Integer.swift"
  "Basic ASN1 Types/ASN1Null.swift"
  "Basic ASN1 Types/ASN1OctetString.swift"
  "Basic ASN1 Types/ASN1Strings.swift"
  "Basic ASN1 Types/ArraySliceBigint.swift"
  "Basic ASN1 Types/GeneralizedTime.swift"
  "Basic ASN1 Types/ObjectIdentifier.swift"
  "Basic ASN1 Types/PEMDocument.swift"
  "Basic ASN1 Types/TimeUtilities.swift"
  "Basic ASN1 Types/UTCTime.swift"
  "Errors.swift")

target_link_libraries(SwiftASN1 PUBLIC
  $<$<NOT:$<PLATFORM_ID:Darwin>>:dispatch>
  $<$<NOT:$<PLATFORM_ID:Darwin>>:Foundation>)
set_target_properties(SwiftASN1 PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_Swift_MODULE_DIRECTORY})

_install_target(SwiftASN1)
set_property(GLOBAL APPEND PROPERTY SWIFT_ASN1_EXPORTS SwiftASN1)
