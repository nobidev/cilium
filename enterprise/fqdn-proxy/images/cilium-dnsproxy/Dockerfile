# Copyright 2020-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:dafe1d5690acd008c6f86482eb69681ad692f5ea@sha256:5ae08955b7a99ca53f79aee0034809519430d91188db2796affe06d08dbd1ea9
ARG CILIUM_RUNTIME_IMAGE=quay.io/cilium/cilium-runtime:65fa0b0a5e0cd4fbd4b243d8f2aba5751fc0eeff@sha256:8ddea1434c9e407ecf6f212b9cd06fdb6955e4895581d8bb100533f9f1f2de99

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
