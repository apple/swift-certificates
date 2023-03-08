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

set(SWIFT_CERTIFICATES_EXPORTS_FILE ${CMAKE_CURRENT_BINARY_DIR}/SwiftCertificatesExports.cmake)
configure_file(SwiftCertificatesConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/SwiftCertificatesConfig.cmake)

get_property(SWIFT_CERTIFICATES_EXPORTS GLOBAL PROPERTY SWIFT_CERTIFICATES_EXPORTS)
export(TARGETS ${SWIFT_CERTIFICATES_EXPORTS} FILE ${SWIFT_CERTIFICATES_EXPORTS_FILE})

