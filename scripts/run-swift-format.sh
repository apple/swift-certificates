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
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftOpenAPIGenerator open source project
##
## Copyright (c) 2023 Apple Inc. and the SwiftOpenAPIGenerator project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftOpenAPIGenerator project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##
set -euo pipefail

function log() { printf -- "** %s\n" "$*" >&2; }
function error() { printf -- "** ERROR: %s\n" "$*" >&2; }
function fatal() { error "$*"; exit 1; }

current_script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
repo_root="$(git -C "${current_script_dir}" rev-parse --show-toplevel)"

swiftformat_bin=${swiftformat_bin:-$(command -v swift-format)} || fatal "❌ swiftformat_bin unset and no swift-format on PATH"

"${swiftformat_bin}" lint \
  --parallel --recursive --strict \
  "${repo_root}/Sources" "${repo_root}/Tests" \
  && swift_format_rc=$? || swift_format_rc=$?

if [[ "${swift_format_rc}" -ne 0 ]]; then
  fatal "❌ Running swift-format produced errors.

  To fix, run the following command:

    % swift-format format --parallel --recursive --in-place Sources Tests
  "
  exit "${swift_format_rc}"
fi

log "✅ Ran swift-format with no errors."
