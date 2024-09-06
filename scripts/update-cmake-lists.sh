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

here=$(pwd)

case "$(uname -s)" in
    Darwin)
        find=gfind # brew install findutils
        ;;
    *)
        # shellcheck disable=SC2209
        find=find
        ;;
esac

function update_cmakelists_source() {
    src_root="$here/Sources/$1"

    # Build an array with the rest of the arguments
    shift
    src_exts=("$@")
    echo "Finding source files (${src_exts[@]}) under $src_root"

    num_exts=${#src_exts[@]}

    # Build file extensions argument for `find`
    declare -a exts_arg
    exts_arg+=(-name "${src_exts[0]}")
    for (( i=1; i<num_exts; i++ ));
    do
        exts_arg+=(-o -name "${src_exts[$i]}")
    done

    # Wrap quotes around each filename since it might contain spaces
    srcs=$($find "${src_root}" -type f \( "${exts_arg[@]}" \) -printf '  "%P"\n' | LC_ALL=POSIX sort)
    echo "$srcs"

    # Update list of source files in CMakeLists.txt
    # The first part in `BEGIN` (i.e., `undef $/;`) is for working with multi-line;
    # the second is so that we can pass in a variable to replace with.
    perl -pi -e 'BEGIN { undef $/; $replace = shift } s/add_library\(([^\n]+)\n([^\)]+)/add_library\($1\n$replace/' "$srcs" "$src_root/CMakeLists.txt"
    echo "Updated $src_root/CMakeLists.txt"
}

update_cmakelists_source "X509" "*.swift"
update_cmakelists_source "_CertificateInternals" "*.swift"

