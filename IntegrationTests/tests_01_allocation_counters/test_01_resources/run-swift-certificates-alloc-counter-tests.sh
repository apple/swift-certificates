#!/bin/bash
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

set -eu
here="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

tmp_dir="/tmp"

while getopts "t:" opt; do
    case "$opt" in
        t)
            tmp_dir="$OPTARG"
            ;;
        *)
            exit 1
            ;;
    esac
done

nio_checkout=$(mktemp -d "$tmp_dir/.swift-nio_XXXXXX")
(
cd "$nio_checkout"
git clone --depth 1 https://github.com/apple/swift-nio
)

shift $((OPTIND-1))

tests_to_run=("$here"/test_*.swift)

if [[ $# -gt 0 ]]; then
    tests_to_run=("$@")
fi

"$nio_checkout/swift-nio/IntegrationTests/allocation-counter-tests-framework/run-allocation-counter.sh" \
    -p "$here/../../.." \
    -m SwiftASN1 \
    -m X509 \
    -s "$here/shared.swift" \
    -t "$tmp_dir" \
    "${tests_to_run[@]}"
