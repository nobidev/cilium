#!/usr/bin/env bash

# Copyright (C) Isovalent, Inc. - All Rights Reserved.

# This script looks at the current state and the environment variables set
# to populate helm values with the matching image versions.
# CL_REGISTRY: select a specific registry, defaults to quay.io/isovalent-dev
# CL_SUFFIX: whether a suffix needs to get appended, defaults to -ubi
# CL_IS_CI: whether an additional -ci suffix needs to get appended, defaults to true
# CL_TAG: the tag to use for in-tree images, defaults to the commit id of the head

set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-releases depName=mikefarah/yq
yq_version=4.45.1  

root_dir=$(git rev-parse --show-toplevel)
values_file="${root_dir}/enterprise/olm/manifests/values.yaml"
registry="${CL_REGISTRY:-quay.io/isovalent-dev}"
is_ci="${CL_IS_CI:-true}"
in_tree_suffix="${CL_SUFFIX:--ubi}"
out_tree_suffix="${CL_SUFFIX:--ubi}"
if [ "${is_ci}" == "true" ]; then
  in_tree_suffix="${in_tree_suffix}-ci"
fi
if [ -z "${CL_TAG+x}" ] ; then
  echo "Using the commit id of the head as tag, set CL_TAG to the desired value otherwise"
  tag="$(git rev-parse HEAD)"
else
  tag="${CL_TAG}"
fi
# Using a temporary file avoid getting a half processed result file if an issue occurs
tmp_file=$(mktemp)
function cleanup {
  rm -rf "${tmp_file}"
}
trap cleanup EXIT
trap cleanup SIGINT

cp ${values_file} ${tmp_file}
# yq_replace makes in place modifications of values.yaml
function yq_replace {
  docker run --rm -v "${tmp_file}":/workdir/values.yaml --user "$(id -u):$(id -g)" mikefarah/yq:${yq_version} e -i "$1" /workdir/values.yaml
}
# yq_replace_csv makes in place modifications of clife.clusterserviceversion.yaml
function yq_replace_csv {
  docker run --rm -v "${root_dir}/enterprise/olm/config/manifests/bases/clife.clusterserviceversion.yaml":/workdir/csv.yaml --user "$(id -u):$(id -g)" mikefarah/yq:${yq_version} e -i "$1" /workdir/csv.yaml
}

# yq_get retrieves values of fields in values.yaml
yq_get_result=""
function yq_get {
  yq_get_result=$(docker run --rm -v "${tmp_file}":/workdir/values.yaml --user "$(id -u):$(id -g)" mikefarah/yq:${yq_version} e "$1" /workdir/values.yaml)
}

# get_digest gives the digest of the image from the image reference and tag
get_digest_result=""
function get_digest {
  get_digest_result=$(${root_dir}/images/scripts/get-image-digest.sh "$1:$2")
}
# $tmp_config gets mounted with yq_replace and -i is used
# Set the image tags
yq_replace ".image.tag = \"${tag}\""
yq_replace ".preflight.image.tag = \"${tag}\""
yq_replace ".operator.image.tag = \"${tag}\""
yq_replace ".hubble.relay.image.tag = \"${tag}\""
yq_replace ".clustermesh.apiserver.image.tag = \"${tag}\""
# Set the image repositories
yq_replace ".image.repository = \"${registry}/cilium${in_tree_suffix}\""
yq_replace ".preflight.image.repository = \"${registry}/cilium${in_tree_suffix}\""
yq_replace ".hubble.relay.image.repository = \"${registry}/hubble-relay${in_tree_suffix}\""
yq_replace ".clustermesh.apiserver.image.repository = \"${registry}/clustermesh-apiserver${in_tree_suffix}\""
yq_replace ".nodeinit.image.repository = \"quay.io/isovalent/startup-script${out_tree_suffix}\""
yq_replace ".certgen.image.repository = \"quay.io/isovalent/certgen${out_tree_suffix}\""
yq_replace ".envoy.image.repository = \"quay.io/isovalent/cilium-envoy${out_tree_suffix}\""
yq_replace ".operator.image.repository = \"${registry}/operator\""
yq_replace ".operator.image.suffix = \"${in_tree_suffix}\""
# Set the image digests and populate related images in the ClusterServiceVersion
related_imgs="["
# cilium agent
yq_get ".image.repository"
img=${yq_get_result}
yq_get ".image.tag"
tag=${yq_get_result}
get_digest "${img}" "${tag}"
digest=${get_digest_result}
yq_replace ".image.digest = \"${digest}\""
related_imgs+="{\"name\": \"agent\",\"image\":\"${registry}/cilium${in_tree_suffix}:${tag}@${digest}\"},"
# preflight
yq_get ".preflight.image.repository"
img=${yq_get_result}
yq_get ".preflight.image.tag"
tag=${yq_get_result}
get_digest "${img}" "${tag}"
digest=${get_digest_result}
yq_replace ".preflight.image.digest = \"${digest}\""
related_imgs+="{\"name\": \"preflight\",\"image\":\"${registry}/cilium${in_tree_suffix}:${tag}@${digest}\"},"
# hubble relay
yq_get ".hubble.relay.image.repository"
img=${yq_get_result}
yq_get ".hubble.relay.image.tag"
tag=${yq_get_result}
get_digest "${img}" "${tag}"
digest=${get_digest_result}
yq_replace ".hubble.relay.image.digest = \"${digest}\""
related_imgs+="{\"name\": \"hubble-relay\",\"image\":\"${registry}/hubble-relay${in_tree_suffix}:${tag}@${digest}\"},"
# clustermesh
yq_get ".clustermesh.apiserver.image.repository"
img=${yq_get_result}
yq_get ".clustermesh.apiserver.image.tag"
tag=${yq_get_result}
get_digest "${img}" "${tag}"
digest=${get_digest_result}
yq_replace ".clustermesh.apiserver.image.digest = \"${digest}\""
related_imgs+="{\"name\": \"clustermesh-apiserver\",\"image\":\"${registry}/clustermesh-apiserver${in_tree_suffix}:${tag}@${digest}\"},"
# startup-script
yq_get ".nodeinit.image.repository"
img=${yq_get_result}
yq_get ".nodeinit.image.tag"
tag=${yq_get_result}
get_digest "${img}" "${tag}"
digest=${get_digest_result}
yq_replace ".nodeinit.image.digest = \"${digest}\""
related_imgs+="{\"name\": \"nodeinit\",\"image\":\"quay.io/isovalent/startup-script${out_tree_suffix}:${tag}@${digest}\"},"
# certgen
yq_get ".certgen.image.repository"
img=${yq_get_result}
yq_get ".certgen.image.tag"
tag=${yq_get_result}
get_digest "${img}" "${tag}"
digest=${get_digest_result}
yq_replace ".certgen.image.digest = \"${digest}\""
related_imgs+="{\"name\": \"certgen\",\"image\":\"quay.io/isovalent/certgen${out_tree_suffix}:${tag}@${digest}\"},"
# envoy
yq_get ".envoy.image.repository"
img=${yq_get_result}
yq_get ".envoy.image.tag"
tag=${yq_get_result}
get_digest "${img}" "${tag}"
digest=${get_digest_result}
yq_replace ".envoy.image.digest = \"${digest}\""
related_imgs+="{\"name\": \"cilium-envoy\",\"image\":\"quay.io/isovalent/cilium-envoy${out_tree_suffix}:${tag}@${digest}\"},"
# operator
yq_get ".operator.image.repository"
img=${yq_get_result}
yq_get ".operator.image.tag"
tag=${yq_get_result}
yq_get ".operator.image.suffix"
op_suffix=${yq_get_result}
get_digest "${img}-generic${op_suffix}" "${tag}"
digest=${get_digest_result}
yq_replace ".operator.image.genericDigest = \"${digest}\""
related_imgs+="{\"name\": \"cilium-operator\",\"image\":\"${registry}/operator-generic${in_tree_suffix}:${tag}@${digest}\"}"
related_imgs+="]"
yq_replace_csv ".spec.relatedImages = ${related_imgs}"
cp ${tmp_file} ${values_file}

echo "values.yaml updated"
