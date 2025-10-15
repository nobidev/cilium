#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

OWNERS="CODEOWNERS"
VOID="isovalent/void"
CMD="go tool github.com/hmarr/codeowners/cmd/codeowners -f ${OWNERS} -o ${VOID}"

FILES=$(${CMD})
if [[ ${FILES} ]] ; then
  echo "Some enterprise-only files are not owned by a team yet."
  echo "Please add entries to ${OWNERS} for the files below:"
  echo "$FILES"
  exit 1
fi
