#!/usr/bin/env bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.
set -x

# TODO: configure renovate
# # renovate: datasource=github-releases depName=mikefarah/yq
yq_version=4.31.1

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

yq_run() {
  docker run -v "${script_dir}":"${script_dir}" --rm -i --user "$(id -u):$(id -g)" mikefarah/yq:${yq_version} "$@"
}
