# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

REGISTRIES ?= quay.io/isovalent

PUSH ?= false

OUTPUT := "type=image"
ifeq ($(PUSH),true)
OUTPUT := "type=registry,push=true"
endif

RUNTIME_IMAGE ?= quay.io/isovalent-dev/cilium-runtime-ubi-dev
LLVM_IMAGE ?= quay.io/isovalent-dev/cilium-llvm-ubi-dev

all-images: lint runtime-image cilium-image operator-image hubble-relay-image

lint:
	scripts/lint.sh

.buildx_builder:
	# see https://github.com/docker/buildx/issues/308
	mkdir -p ../.buildx
	docker buildx create --buildkitd-flags '--debug' > $@

runtime-image: .buildx_builder
	TEST=true ./scripts/build-image.sh cilium-runtime-ubi-dev enterprise/images/runtime $(OUTPUT) "$$(cat .buildx_builder)" $(LLVM_IMAGE) $(REGISTRIES)

update-runtime-image:
	echo "TODO: populate the script: scripts/update-cilium-runtime-image.sh $(RUNTIME_IMAGE)"

check-runtime-image:
	echo "TODO: populate the script: CHECK=true scripts/check-cilium-runtime-image.sh $(RUNTIME_IMAGE)"

cilium-image: .buildx_builder
	# TODO: envoy image should also be passed as an argument, this should be made an array
	ROOT_CONTEXT=true ./scripts/build-image.sh cilium-ubi-dev images/cilium $(OUTPUT) "$$(cat .buildx_builder)" $(RUNTIME_IMAGE) $(REGISTRIES)

operator-image: .buildx_builder
	ROOT_CONTEXT=true ./scripts/build-image.sh operator-ubi-dev ../../images/operator $(OUTPUT) "$$(cat .buildx_builder)" $(REGISTRIES)

hubble-relay-image: .buildx_builder
	ROOT_CONTEXT=true ./scripts/build-image.sh hubble-relay-ubi-dev ../../images/hubble-relay $(OUTPUT) "$$(cat .buildx_builder)" $(REGISTRIES)

update-envoy-image:
	echo "TODO: update the reference to the actual envoy proxy UBI image, cf: scripts/update-cilium-envoy-image.sh, to pass to the Dockerfile of the Cilium agent"

check-envoy-image:
	echo "TODO: check whether we have the reference to the actual envoy proxy UBI image, cf:scripts/check-cilium-envoy-image.sh to pass to the Dockerfile of the Cilium agent."

# TODO: Clarify whether it is better to retrieve the references to the UBI images used in Cilium agent Dockerfile dynamically or to have them stored in a file.
