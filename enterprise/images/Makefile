# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

REGISTRIES ?= quay.io/isovalent

PUSH ?= false

SUFFIX ?= -dev

OUTPUT := "type=image"
ifeq ($(PUSH),true)
OUTPUT := "type=registry,push=true"
endif

# renovate: datasource=docker
RUNTIME_IMAGE ?= quay.io/isovalent-dev/cilium-runtime-ubi:cd74ebc98d21b15e6fa66d02e7b73cccb75f5566
# renovate: datasource=docker
LLVM_IMAGE ?= quay.io/isovalent-dev/cilium-llvm-ubi:1754712783-48bbfc6@sha256:b673ca26acfc574d815c231814707ffa6e39e039450ce95bf296a436f4ff22e9
# renovate: datasource=docker
UBI_IMAGE ?= registry.redhat.io/ubi9/ubi-minimal:9.6@sha256:8d905a93f1392d4a8f7fb906bd49bf540290674b28d82de3536bb4d0898bf9d7
IMAGE_TAG ?= $$(../../images/scripts/make-image-tag.sh)

PLATFORMS ?= unspecified

all-images: lint runtime-image cilium-image operator-image hubble-relay-image

lint:
	scripts/lint.sh

.buildx_builder:
	# see https://github.com/docker/buildx/issues/308
	mkdir -p ../.buildx
	docker buildx create --buildkitd-flags '--debug' > $@

runtime-image: .buildx_builder
	ROOT_CONTEXT=true TEST=true ./scripts/build-image.sh cilium-runtime-ubi$(SUFFIX) enterprise/images/runtime $(OUTPUT) $(PLATFORMS) "$$(cat .buildx_builder)" "--build-arg CILIUM_LLVM_IMAGE=${LLVM_IMAGE}" $(REGISTRIES)

update-runtime-image:
	echo "TODO: populate the script: scripts/update-cilium-runtime-image.sh $(RUNTIME_IMAGE)"

check-runtime-image:
	echo "TODO: populate the script: CHECK=true scripts/check-cilium-runtime-image.sh $(RUNTIME_IMAGE)"

cilium-image: .buildx_builder
	# The build is split into two stages so that the standard Dockerfile and context can be used and the specificities for Red Hat get layered on top of it without modification of the OSS files:
	# - license file
	# - labels
	# Forcing push on the intermediary image as buildx always pulls from registry and standard docker does not support manifest lists
	# TODO: envoy image should also be passed as an argument
	ROOT_CONTEXT=true ./scripts/build-image.sh cilium-ubi-stage $(abspath ../../images/cilium) "type=registry,push=true" $(PLATFORMS) "$$(cat .buildx_builder)" "--build-arg CILIUM_RUNTIME_IMAGE=$(RUNTIME_IMAGE) --target=release" $(REGISTRIES)
	./scripts/build-image.sh cilium-ubi$(SUFFIX) enterprise/images/cilium $(OUTPUT) $(PLATFORMS) "$$(cat .buildx_builder)" "--build-arg BASE_IMAGE=$(REGISTRIES)/cilium-ubi-stage:$(IMAGE_TAG) --build-arg BUILD_DATE=$$(date -u +'%Y-%m-%dT%H:%M:%SZ') --build-arg VERSION=$(IMAGE_TAG) $(EXTRA_ARGS)" $(REGISTRIES)

operator-image: .buildx_builder
	# The build is split into two stages so that the standard Dockerfile and context can be used and the specificities for Red Hat get layered on top of it without modification of the OSS files:
	# - license file
	# - labels
	# Forcing push on the intermediary image as buildx always pulls from registry and standard docker does not support manifest lists
	ROOT_CONTEXT=true ./scripts/build-image.sh operator-ubi-stage $(abspath ../../images/operator) "type=registry,push=true" $(PLATFORMS) "$$(cat .buildx_builder)" "--build-arg BASE_IMAGE=$(UBI_IMAGE) --build-arg OPERATOR_VARIANT=operator-generic --target=release" $(REGISTRIES)
	./scripts/build-image.sh operator-generic-ubi$(SUFFIX) enterprise/images/operator $(OUTPUT) $(PLATFORMS) "$$(cat .buildx_builder)" "--build-arg BASE_IMAGE=$(REGISTRIES)/operator-ubi-stage:$(IMAGE_TAG) --build-arg BUILD_DATE=$$(date -u +'%Y-%m-%dT%H:%M:%SZ') --build-arg VERSION=$(IMAGE_TAG) $(EXTRA_ARGS)" $(REGISTRIES)

hubble-relay-image: .buildx_builder
	# The build is split into two stages so that the standard Dockerfile and context can be used and the specificities for Red Hat get layered on top of it without modification of the OSS files:
	# - license file
	# - labels
	# Forcing push on the intermediary image as buildx always pulls from registry and standard docker does not support manifest lists
	ROOT_CONTEXT=true ./scripts/build-image.sh hubble-relay-ubi-stage $(abspath ../../images/hubble-relay) "type=registry,push=true" $(PLATFORMS) "$$(cat .buildx_builder)" "--build-arg BASE_IMAGE=$(UBI_IMAGE) --target=release" $(REGISTRIES)
	./scripts/build-image.sh hubble-relay-ubi$(SUFFIX) enterprise/images/hubble-relay $(OUTPUT) $(PLATFORMS) "$$(cat .buildx_builder)" "--build-arg BASE_IMAGE=$(REGISTRIES)/hubble-relay-ubi-stage:$(IMAGE_TAG) --build-arg BUILD_DATE=$$(date -u +'%Y-%m-%dT%H:%M:%SZ') --build-arg VERSION=$(IMAGE_TAG) $(EXTRA_ARGS)" $(REGISTRIES)

clustermesh-apiserver-image: .buildx_builder
	# The build is split into two stages so that the standard Dockerfile and context can be used and the specificities for Red Hat get layered on top of it without modification of the OSS files:
	# - license file
	# - labels
	# Forcing push on the intermediary image as buildx always pulls from registry and standard docker does not support manifest lists
	ROOT_CONTEXT=true ./scripts/build-image.sh clustermesh-apiserver-ubi-stage $(abspath ../../images/clustermesh-apiserver) "type=registry,push=true" $(PLATFORMS) "$$(cat .buildx_builder)" "--build-arg BASE_IMAGE=$(UBI_IMAGE) --target=release" $(REGISTRIES)
	./scripts/build-image.sh clustermesh-apiserver-ubi$(SUFFIX) enterprise/images/clustermesh-apiserver $(OUTPUT) $(PLATFORMS) "$$(cat .buildx_builder)" "--build-arg BASE_IMAGE=$(REGISTRIES)/clustermesh-apiserver-ubi-stage:$(IMAGE_TAG) --build-arg BUILD_DATE=$$(date -u +'%Y-%m-%dT%H:%M:%SZ') --build-arg VERSION=$(IMAGE_TAG) $(EXTRA_ARGS)" $(REGISTRIES)

update-envoy-image:
	echo "TODO: update the reference to the actual envoy proxy UBI image, cf: scripts/update-cilium-envoy-image.sh, to pass to the Dockerfile of the Cilium agent"

check-envoy-image:
	echo "TODO: check whether we have the reference to the actual envoy proxy UBI image, cf:scripts/check-cilium-envoy-image.sh to pass to the Dockerfile of the Cilium agent."

# TODO: Clarify whether it is better to retrieve the references to the UBI images used in Cilium agent Dockerfile dynamically or to have them stored in a file.
