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
UBI_IMAGE ?= registry.redhat.io/ubi9/ubi-minimal

all-images: lint runtime-image cilium-image operator-image hubble-relay-image

lint:
	scripts/lint.sh

.buildx_builder:
	# see https://github.com/docker/buildx/issues/308
	mkdir -p ../.buildx
	docker buildx create --buildkitd-flags '--debug' > $@

runtime-image: .buildx_builder
	TEST=true ./scripts/build-image.sh cilium-runtime-ubi-dev enterprise/images/runtime $(OUTPUT) "$$(cat .buildx_builder)" "--build-arg CILIUM_LLVM_IMAGE=${LLVM_IMAGE}" $(REGISTRIES)

update-runtime-image:
	echo "TODO: populate the script: scripts/update-cilium-runtime-image.sh $(RUNTIME_IMAGE)"

check-runtime-image:
	echo "TODO: populate the script: CHECK=true scripts/check-cilium-runtime-image.sh $(RUNTIME_IMAGE)"

cilium-image: .buildx_builder
	# TODO: envoy image should also be passed as an argument
	ROOT_CONTEXT=true ./scripts/build-image.sh cilium-ubi-dev images/cilium $(OUTPUT) "$$(cat .buildx_builder)" "--build-arg CILIUM_RUNTIME_IMAGE=$(RUNTIME_IMAGE) --target=release" $(REGISTRIES)

operator-image: .buildx_builder
	# The build is split into two stages so that the standard Dockerfile and context can be used and the specificities for Red Hat get layered on top of it without modification of the OSS files:
	# - license file
	# - labels
	# Forcing push on the intermediary image as buildx always pulls from registry and standard docker does not support manifest lists
	ROOT_CONTEXT=true PUSH=true ./scripts/build-image.sh operator-ubi-stage $(abspath ../../images/operator) $(OUTPUT) "$$(cat .buildx_builder)" "--build-arg BASE_IMAGE=$(UBI_IMAGE) --build-arg OPERATOR_VARIANT=operator-generic --target=release" $(REGISTRIES)
	./scripts/build-image.sh operator-ubi-generic enterprise/images/operator $(OUTPUT) "$$(cat .buildx_builder)" "--build-arg BASE_IMAGE=$(REGISTRIES)/operator-ubi-stage:$$(../../images/scripts/make-image-tag.sh) --build-arg BUILD_DATE=$$(date -u +'%Y-%m-%dT%H:%M:%SZ')" $(REGISTRIES)

hubble-relay-image: .buildx_builder
	# The build is split into two stages so that the standard Dockerfile and context can be used and the specificities for Red Hat get layered on top of it without modification of the OSS files:
	# - license file
	# - labels
	# Forcing push on the intermediary image as buildx always pulls from registry and standard docker does not support manifest lists
	ROOT_CONTEXT=true PUSH=true ./scripts/build-image.sh hubble-relay-ubi-stage $(abspath ../../images/hubble-relay) $(OUTPUT) "$$(cat .buildx_builder)" "--build-arg BASE_IMAGE=$(UBI_IMAGE) --target=release" $(REGISTRIES)
	./scripts/build-image.sh hubble-relay-ubi enterprise/images/hubble-relay $(OUTPUT) "$$(cat .buildx_builder)" "--build-arg BASE_IMAGE=$(REGISTRIES)/hubble-relay-ubi-stage:$$(../../images/scripts/make-image-tag.sh) --build-arg BUILD_DATE=$$(date -u +'%Y-%m-%dT%H:%M:%SZ')" $(REGISTRIES)

clustermesh-apiserver-image: .buildx_builder
	# The build is split into two stages so that the standard Dockerfile and context can be used and the specificities for Red Hat get layered on top of it without modification of the OSS files:
	# - license file
	# - labels
	# Forcing push on the intermediary image as buildx always pulls from registry and standard docker does not support manifest lists
	ROOT_CONTEXT=true PUSH=true ./scripts/build-image.sh clustermesh-apiserver-ubi-stage $(abspath ../../images/clustermesh-apiserver) $(OUTPUT) "$$(cat .buildx_builder)" "--build-arg BASE_IMAGE=$(UBI_IMAGE) --target=release" $(REGISTRIES)
	./scripts/build-image.sh clustermesh-apiserver-ubi enterprise/images/clustermesh-apiserver $(OUTPUT) "$$(cat .buildx_builder)" "--build-arg BASE_IMAGE=$(REGISTRIES)/clustermesh-apiserver-ubi-stage:$$(../../images/scripts/make-image-tag.sh) --build-arg BUILD_DATE=$$(date -u +'%Y-%m-%dT%H:%M:%SZ')" $(REGISTRIES)

update-envoy-image:
	echo "TODO: update the reference to the actual envoy proxy UBI image, cf: scripts/update-cilium-envoy-image.sh, to pass to the Dockerfile of the Cilium agent"

check-envoy-image:
	echo "TODO: check whether we have the reference to the actual envoy proxy UBI image, cf:scripts/check-cilium-envoy-image.sh to pass to the Dockerfile of the Cilium agent."

# TODO: Clarify whether it is better to retrieve the references to the UBI images used in Cilium agent Dockerfile dynamically or to have them stored in a file.
