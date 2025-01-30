# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0
include ../../../../../../Makefile.defs

CILIUM_BUILDER_IMAGE=$(shell grep -oP 'ARG CILIUM_BUILDER_IMAGE=\K.+' ${ROOT_DIR}/images/cilium/Dockerfile)

.PHONY: proto
proto:
	$(QUIET)$(CONTAINER_ENGINE) container run --rm \
		--volume $(CURDIR):/src \
		--user "$(shell id -u):$(shell id -g)" \
		$(CILIUM_BUILDER_IMAGE) \
		make -C /src -f Makefile.protoc
