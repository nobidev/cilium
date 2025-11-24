#!/usr/bin/env bash

#  Copyright (C) Isovalent, Inc. - All Rights Reserved. 
# 
#  NOTICE: All information contained herein is, and remains the property of 
#  Isovalent Inc and its suppliers, if any. The intellectual and technical 
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers 
#  and may be covered by U.S. and Foreign Patents, patents in process, and are 
#  protected by trade secret or copyright law.  Dissemination of this information 
#  or reproduction of this material is strictly forbidden unless prior written 
#  permission is obtained from Isovalent Inc.

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

image_full=${1}
root_dir="$(git rev-parse --show-toplevel)"

cd "${root_dir}"

image="quay.io/isovalent-dev/cilium-runtime-wfi"

# shellcheck disable=SC2207
used_by=($(find . -type f -name runtime-image-enterprise.txt -print0 | xargs -0 git grep -l "${image}"))

for i in "${used_by[@]}" ; do
  sed -E "s#${image}:.*#${image_full}#" "${i}" > "${i}.sedtmp" && mv "${i}.sedtmp" "${i}"
done

do_check="${CHECK:-false}"
if [ "${do_check}" = "true" ] ; then
  git diff --exit-code "${used_by[@]}" || (echo "Runtime images out of date, " \
    "see https://docs.cilium.io/en/latest/contributing/development/images/#update-cilium-builder-runtime-images." && \
    exit 1)
fi
