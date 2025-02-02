#!/usr/bin/env bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.

function fetch_percli() {
    repo=$1
    version=$2
    dst_dir=$3

    # Detect OS
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')

    # Normalize OS names
    case "$OS" in
        linux) OS="linux" ;;
        darwin) OS="darwin" ;;
        *) echo "Unsupported OS: $OS" && exit 1 ;;
    esac

    # Detect Architecture
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH="amd64" ;;
        aarch64 | arm64) ARCH="arm64" ;;
        *) echo "Unsupported architecture: $ARCH" && exit 1 ;;
    esac

    # Construct the download URL
    BINARY="perses_${version}_${OS}_${ARCH}.tar.gz"
    CLIURL="${repo}/releases/download/v${version}/${BINARY}"
    PERCLI=${dst_dir}/percli
    # fetch percli
    if [ ! -f "${PERCLI}" ]; then
        curl -L "${CLIURL}" | tar -xvz --wildcards 'percli'
        mv --force percli "${PERCLI}"
    fi
}

function convert_files() {
    repo=$1
    version=$2
    tmp_dir=$3
    src_dir=$4
    dst_dir=$5
    percli=$6

    # checkout the perses schemas
    cd "${tmp_dir}"
    git clone --no-checkout --filter=blob:none --sparse ${repo}
    cd perses
    git fetch --tags
    git checkout tags/v${version}
    git sparse-checkout init --cone
    git sparse-checkout set cue cue.mod
    git checkout

    schemas=${tmp_dir}/perses/cue/schemas

    # iterate over the subfolders
    echo "Processing folder: ${src_dir}"
    files=$(find "${src_dir}" -type f)
    for file in ${files}; do
        filename=$(basename "${file}" .${file##*.})
        echo "Migrating: ${filename}"
        echo "To: ${dst_dir}/${filename}.yaml"

        # We do an offline dashboard migration with explicit schema validation
        # this will work for v0.50.1 but the subsequent versions will migrate
        # to using a plugin model where the --schemas.* are removed
        #
        # After the migration we do remove the datasource as we're going to use
        # perses per project datasource configured accordingly.
        # Finally we are making sure the charts have the ILB project set in the metadata.
        ${percli} migrate \
            -f ${file} \
            --output yaml \
            --schemas.queries "${schemas}/queries" \
            --schemas.variables "${schemas}/variables" \
            --schemas.charts "${schemas}/panels" \
            | sed '/datasource:/,/name: *\($\({datasource}\|\datasource\)\|prometheus\)/d' \
            | sed 's/project: *""/project: "ILB"/' \
            > "${dst_dir}/${filename}.yaml"
    done
}
