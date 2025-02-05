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
ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:60b838bf27ad75ca16cc2c8744cb30d277b0c22f@sha256:7f44e1c2f8c11f342cba5a07ca7881db1e0c8bb2633f641c945ad68ab6eed21c

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
    -C enterprise/cilium-cli all install

FROM ${BASE_IMAGE} AS release

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH

LABEL maintainer="support@isovalent.com"
WORKDIR /root/app
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/local/bin/cilium /usr/local/bin/cilium
ENTRYPOINT ["cilium"]
