#!/usr/bin/env bash

# Copyright (C) Isovalent, Inc. - All Rights Reserved.

# This script generates the release-config.yaml file for the Red Hat certified operators repository.
# Based on this file a newly published bundle gets added to the defined channels and Red Hat catalogs
# automatically updated accordingly.
# CL_TAG: the tag use ford the release version
# CL_RH_REPO: the location of the Red Hat repository

set -o errexit
set -o pipefail
set -o nounset

if [ -z "${CL_TAG+x}" ] ; then
  echo "CL_TAG, containing the release version number, must be provided"
  exit 1
fi
tag="${CL_TAG}"
echo "tag: ${tag}"
rh_repo="${CL_RH_REPO}"
echo "Red Hat certified operators repo: ${rh_repo}"
root_dir=$(git rev-parse --show-toplevel)

# renovate: datasource=github-releases depName=mikefarah/yq
yq_version=4.46.1

bundle_major=$(echo "$CL_TAG" | cut -d \. -f 1)
bundle_major=${bundle_major#v}
bundle_minor=$(echo "$CL_TAG" | cut -d \. -f 2)
bundle_zversion=$(echo "$CL_TAG" | cut -d \. -f 3-)
bundle_zversion="${bundle_zversion,,}"
release_file=release-config.yaml
template_file=template.yaml

# Retrieve existing channel entries
entries=$(docker run --rm -v "${rh_repo}/operators/isovalent-networking/catalog-templates":/workdir mikefarah/yq:${yq_version} ".entries[] | select (.schema == \"olm.channel\" and .name == \"${bundle_major}.${bundle_minor}\") | .entries[].name" /workdir/${template_file})
if [ -z "${entries}" ]; then
  previous_minor=$(( bundle_minor - 1 ))
  entries=$(docker run --rm -v "${rh_repo}/operators/isovalent-networking/catalog-templates":/workdir mikefarah/yq:${yq_version} ".entries[] | select (.schema == \"olm.channel\" and .name == \"${bundle_major}.${previous_minor}\") | .entries[].name" /workdir/${template_file})
  if [ -z "${entries}" ]; then
    echo "New major release!!!"
    latest_entry=""
    skip_from=""
  else 
    sorted=$(echo "${entries}" | sort -n)
    latest_entry=$(echo "${sorted}" | tail -1)
    # Between different minors allow skipping from the latest patch release of the previous minor at release time
    skip_from=${latest_entry}
  fi
else
  echo "entries: $entries"
  sorted=$(echo "${entries}" | sort -n)
  latest_entry=$(echo "${sorted}" | tail -1)
  # Allow skipping patch releases for the same minor version
  skip_from=$(echo "${sorted}" | head -1)
fi

template="---
catalog_templates:
  - template_name: template.yaml
    channels: [\"${bundle_major}.${bundle_minor}\"]"
if [ -n "${latest_entry}" ]; then
  template="${template}
    replaces: ${latest_entry}"
fi
if [ -n "${skip_from}" ]; then
  skip_from_major=$(echo "${skip_from}" | cut -d \. -f 1)
  skip_from_major=${skip_from_major#v}
  skip_from_minor=$(echo "${skip_from}" | cut -d \. -f 2)
  skip_from_zversion=$(echo "${skip_from}" | cut -d \. -f 3-)
  skip_from_zversion="${skip_from_zversion,,}"
  template="${template}
    skipRange: \">=${skip_from_major}.${skip_from_minor}.${skip_from_zversion} <${tag}\""
fi
echo "template:
${template}"
echo "${template}" > ${rh_repo}/operators/isovalent-networking/${tag}/${release_file}
