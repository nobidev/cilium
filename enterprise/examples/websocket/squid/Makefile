DOCKER := $(QUIET)DOCKER_BUILDKIT=1 docker buildx
DOCKER_PLATFORMS := --platform=linux/arm64,linux/amd64
DOCKER_BUILDER := $(shell docker buildx ls | grep -E -e "[a-zA-Z0-9-]+ \*" | cut -d ' ' -f1)
ifneq (,$(filter $(DOCKER_BUILDER),default desktop-linux))
  DOCKER_BUILDKIT_DRIVER :=
  ifdef DOCKER_BUILDKIT_IMAGE
    DOCKER_BUILDKIT_DRIVER := --driver docker-container --driver-opt image=$(DOCKER_BUILDKIT_IMAGE)
  endif
  BUILDER_SETUP := $(shell docker buildx create $(DOCKER_PLATFORMS) $(DOCKER_BUILDKIT_DRIVER) --use)
  DOCKER_BUILDER := $(shell docker buildx ls | grep -E -e "[a-zA-Z0-9-]+ \*" | cut -d ' ' -f1)
endif
ifneq ($(DOCKER_BUILDER),default)
  # Only insert '--push' if user did not pass a conflicting '--output' option
  ifeq ($(findstring --output,$(DOCKER_BUILD_OPTS)),)
    ifeq ($(findstring --load,$(DOCKER_BUILD_OPTS)),)
      DOCKER_BUILD_OPTS += --push
    endif
  endif
  DOCKER_BUILD_OPTS += $(DOCKER_PLATFORMS)
endif
$(info Using Docker Buildx builder "$(DOCKER_BUILDER)" with build flags "$(DOCKER_BUILD_OPTS)".)

.PHONY: squid-proxy
squid-proxy: Dockerfile
	$(DOCKER) build $(DOCKER_BUILD_OPTS) -t jrajahalme/squid-proxy .
