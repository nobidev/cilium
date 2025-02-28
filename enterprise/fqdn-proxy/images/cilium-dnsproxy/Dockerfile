# Copyright 2020-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:94e69b5e6672825d352b9954b6eb4e3a39eff358@sha256:43c9df4b6ad86153478cbac05722cbb915e8048f3ccc452ccf7c920cc7425c2b
ARG CILIUM_RUNTIME_IMAGE=quay.io/cilium/cilium-runtime:43196ba8f707bc4c7b9addd6cbf906d9c0eb8df4@sha256:ff897a20231d9de65133d999d14290b1894f77709e4b1f54d5946d90645076ed

#
# Cilium incremental build. Should be fast given builder-deps is up-to-date!
#
# cilium-builder tag is the date on which the compatible build image
# was pushed.  If a new version of the build image is needed, it needs
# to be tagged with a new date and this file must be changed
# accordingly.  Keeping the old images available will allow older
# versions to be built while allowing the new versions to make changes
# that are not backwards compatible.
#
FROM --platform=${BUILDPLATFORM} ${CILIUM_BUILDER_IMAGE} AS builder

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
ARG NOSTRIP
ARG NOOPT
ARG LOCKDEBUG
ARG RACE
ARG V

WORKDIR /go/src/github.com/cilium/cilium
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg,type=cache \
    make GOARCH=${TARGETARCH} RACE=${RACE} NOSTRIP=${NOSTRIP} NOOPT=${NOOPT} LOCKDEBUG=${LOCKDEBUG} V=${V} \
    DESTDIR=/tmp/install/${TARGETOS}/${TARGETARCH} -C enterprise/fqdn-proxy all install

FROM ${CILIUM_RUNTIME_IMAGE} AS release
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /tmp/install/${TARGETOS}/${TARGETARCH}/usr/bin/dnsproxy /usr/bin/dnsproxy
WORKDIR /
ENV GOPS_CONFIG_DIR=/
CMD ["/usr/bin/dnsproxy"]
