# Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Isovalent Inc and its suppliers, if any. The intellectual and technical
# concepts contained herein are proprietary to Isovalent Inc and its suppliers
# and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.  Dissemination of this information
# or reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Isovalent Inc.

ARG BASE_IMAGE=scratch
ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:a18c9a04e531dd641801cfe85b171deaeda8e0f8@sha256:d398e6f3b2ed8cad465dcef79869725a25f9c4fef9af7224a08ced697d547ff4

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the platform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${CILIUM_BUILDER_IMAGE} AS builder

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
# MODIFIERS are extra arguments to be passed to make at build time.
ARG MODIFIERS

WORKDIR /go/src/github.com/cilium/cilium
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${TARGETARCH} DESTDIR=/out/${TARGETOS}/${TARGETARCH} $(echo $MODIFIERS | tr -d '"') \
    -C cilium-cli install

FROM ${BASE_IMAGE} AS release

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH

LABEL maintainer="support@isovalent.com"
WORKDIR /root/app
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/local/bin/cilium /usr/local/bin/cilium
ENTRYPOINT ["cilium"]
