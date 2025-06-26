#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

if ! go run ${SCRIPT_ROOT}/../../enterprise/tools/map-testowners > ${SCRIPT_ROOT}/../../TESTOWNERS.enterprise; then
    >&2 echo "hint: enterprise/tools/map-testowners has maps to track teams used in the"
    >&2 echo "      CODEOWNERS file, and to map open source teams to internal teams. These"
    >&2 echo "      need to be updated whenever you make changes to the CODEOWNERS file."
    exit 1
fi
