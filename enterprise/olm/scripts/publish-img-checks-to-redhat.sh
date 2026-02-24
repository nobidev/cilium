#!/usr/bin/env bash

# Copyright (C) Isovalent, Inc. - All Rights Reserved.

# This script runs Red Hat preflight checks against the release images and publish the results.
# CL_TAG: the tag use ford the release version
# CL_PYXIS_TOKEN: the authentication token for Red Hat pyxis API

set -o errexit
set -o pipefail
set -o nounset

if [ -z "${CL_TAG+x}" ] ; then
  echo "CL_TAG, containing the release version number, must be provided"
  exit 1
fi
tag="${CL_TAG}"
echo "tag: ${tag}"
submit_res="${CL_SUBMIT:-false}"

# preflight runs Red Hat container checks
function preflight {
  image="$1"
  token="$2"
  component_id="$3"
  submit="$4"
  output="$5"
  cmd="check container ${image} \
          --pyxis-api-token=${token} \
          --certification-component-id=${component_id}"
  if [ ${submit} = true ]; then
    cmd="$cmd \
	  --submit"
  fi
  echo "docker run --rm quay.io/opdev/preflight:stable ${cmd}  > $output"
  docker run --rm quay.io/opdev/preflight:stable ${cmd}  > $output
}

function preflight-eval {
  result_file="$1"
  for result in $(cat ${result_file} | jq '.passed'); do
     if [ $result != true ]; then
       return 1
     fi
  done
  return 0
}

res="preflight-res.json"
image="quay.io/isovalent/certgen-ubi:${tag}"
component_id="67e510bca8b964f645ea917c"
declare -A images
images+=( [quay.io/isovalent/certgen-ubi]='67e510bca8b964f645ea917c' )
images+=( [quay.io/isovalent/cilium-envoy-ubi]='67e26859ba4cf5e133ebf57e' )
images+=( [quay.io/isovalent/cilium-ubi]='67e1161434298d081056926a' )
images+=( [quay.io/isovalent/clife]='682318ae567dc9a13d0e849b' )
images+=( [quay.io/isovalent/clustermesh-apiserver-ubi]='67e24f5acc50155a8ce3c950' )
images+=( [quay.io/isovalent/hubble-relay-ubi]='67e2482773fd1d2194aab2c3' )
images+=( [quay.io/isovalent/operator-generic-ubi]='67e134c5c66279ded73d5d6f' )
images+=( [quay.io/isovalent/startup-script-ubi]='67e50d549096ba2e8e40446d' )
images+=( [quay.io/isovalent/kubectl-ubi]='699dac1e3fbf700b49c88f7d' )

for image in "${!images[@]}"; do
  preflight $image:${tag} $CL_PYXIS_TOKEN ${images[$image]} false $res
  if ! preflight-eval $res ; then
    echo "Preflight checks failed for image: ${image}:${tag}"
    cat $res
    exit 1
  fi
done
echo "Preflight checks passed"

if [ "${submit_res}" == "true" ]; then
  for image in "${!images[@]}"; do
    preflight $image:${tag} $CL_PYXIS_TOKEN ${images[$image]} true $res
    if ! preflight-eval $res ; then
      echo "Preflight checks failed during submission for image: ${image}:${tag}"
      cat $res
      exit 1
    fi
  done
  echo "Preflight results submitted"
else
   echo "Preflight results submission disabled"
fi
