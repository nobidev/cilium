#!/usr/bin/env bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker rm -f app1 2>/dev/null
docker rm -f app2 2>/dev/null
docker rm -f app3 2>/dev/null

docker rm -f frr 2>/dev/null

