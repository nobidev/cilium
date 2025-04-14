#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_dir="$(cd "${script_dir}/.." && pwd)"
cmdref_dir="${script_dir}/cmdref"

generators=(
    "enterprise/cilium-dbg/cilium-dbg cmdref"
    "enterprise/daemon/cilium-agent cmdref"
    "enterprise/clustermesh-apiserver/clustermesh-apiserver cmdref"
    "enterprise/operator/cilium-operator cmdref"
    "enterprise/operator/cilium-operator-aws cmdref"
    "enterprise/operator/cilium-operator-azure cmdref"
    "enterprise/operator/cilium-operator-generic cmdref"
    "enterprise/operator/cilium-operator-alibabacloud cmdref"
    "enterprise/bugtool/cilium-bugtool cmdref"

    "cilium-cli/cilium cmdref"
    "cilium-health/cilium-health cmdref"
)

for g in "${generators[@]}" ; do
    ${source_dir}/${g} "${cmdref_dir}"
done
