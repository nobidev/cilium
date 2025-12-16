# Copyright 2020-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:acc6214750a75465edd69451692572f35efba34d@sha256:2b069f0b1296ae760c70f2fc533faf0d851b01c7b6fa0925992cef862d31ef92
ARG CILIUM_RUNTIME_IMAGE=quay.io/cilium/cilium-runtime:23ac447b0df25d46d979589c1fd6d38f66e42bad@sha256:c691818639838e88ed48b3dca0e65fc6d088387ac99fa5551fa6a92f96875352

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
