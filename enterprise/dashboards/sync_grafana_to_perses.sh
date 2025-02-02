#!/usr/bin/env bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

. "${script_dir}"/perses_cli.sh

VERSION="0.50.1"
REPO=https://github.com/perses/perses

tmp_dir=$(mktemp -d -t perses-XXXXXXXXXX)
trap cleanup EXIT

function cleanup() {
    echo "Cleanup"
    rm -rf -- "$tmp_dir"
}

fetch_percli ${REPO} ${VERSION} "${tmp_dir}"

PERCLI=${tmp_dir}/percli

# find all subfolders in the script folder
subfolders=$(find "${script_dir}" -mindepth 1 -maxdepth 1 -type d)

# iterate over the subfolders
for folder in ${subfolders}; do
    echo "Processing folder: ${folder}"
    mkdir -p "${folder}/perses"

    convert_files ${REPO} ${VERSION} "${tmp_dir}" "${folder}/grafana" "${folder}/perses" "${PERCLI}"
done
