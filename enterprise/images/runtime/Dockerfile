# Copyright (C) Isovalent, Inc. - All Rights Reserved.

ARG TESTER_IMAGE=quay.io/cilium/image-tester:0a7ee27812441d95926aec83929d97e93ce96aae@sha256:e96542b4f71dbc9cbe77feaf5b1fa9bd5e13122ee6418094731212f1c5667c67
ARG UBI_MINI_IMAGE=registry.redhat.io/ubi9/ubi-minimal@sha256:14f14e03d68f7fd5f2b18a13478b6b127c341b346c86b6e0b886ed2b7573b8e0
ARG GOLANG_IMAGE=docker.io/library/golang:1.24.0@sha256:2b1cbf278ce05a2a310a3d695ebb176420117a8cfcfcc4e5e68a1bef5f6354da
# TODO: This needs to be replaced by the enterprise UBI based version when available.
ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:1732033893-de666b6@sha256:ee005bd47b20f78a727c06fdf2275861848be7acd242603c82f86ca8faaeda90
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:5a9c4852a21287686009bfe1cdc1fed6e7aabdea@sha256:188e398ee30456373530698d0d29de66dda0c4428068ea430027ceb7e9c15b7c
# TODO: to be replaced by a released UBI based compiler image
ARG COMPILERS_IMAGE=quay.io/frederic_giloux/image-compilers-ubi:1740135205-66ff39e-wip

ARG VERSION=0.0.0-dev
ARG REVISION=000000

FROM ${CILIUM_LLVM_IMAGE} AS llvm-dist
FROM ${CILIUM_BPFTOOL_IMAGE} AS bpftool-dist
FROM ${COMPILERS_IMAGE} AS compilers

FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} AS gops-cni-builder

RUN apt-get update && apt-get install -y binutils-aarch64-linux-gnu binutils-x86-64-linux-gnu

# build-gops.sh will build both archs at the same time
WORKDIR /go/src/github.com/isovalent/cilium/enterprise/images/runtime
RUN --mount=type=bind,readwrite,target=. --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
    ./build-gops.sh
# download-cni.sh will build both archs at the same time
RUN --mount=type=bind,readwrite,target=. --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
    ./download-cni.sh

FROM ${UBI_MINI_IMAGE} AS release

LABEL name="Isovalent UBI runtime image" \
      maintainer="support@isovalent.com" \
      vendor="Isovalent" \
      release="1" \
      summary="Isovalent runtime image based on Red Hat Universal Base Image" \
      description="This image extends Red Hat UBI image with generic tooling used by Isovalent images" \
      org.opencontainers.image.authors="Isovalent" \
      org.opencontainers.image.url="https://isovalent.com" \
      org.opencontainers.image.documentation="https://isovalent.com/product" \
      org.opencontainers.image.vendor="Isovalent, part of Cisco" \
      org.opencontainers.image.title="Isovalent UBI runtime image" \
      org.opencontainers.image.description="This image extends Red Hat UBI image with generic tooling used by Isovalent images"

COPY LICENSE /usr/share/licenses/isovalent/

WORKDIR /go/src/github.com/isovalent/cilium/enterprise/images/runtime
# TODO: the WORKDIR instruction should be able to use the "." instead of full path RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime \
RUN --mount=type=bind,readwrite,target=. ./install-runtime-deps.sh

RUN --mount=type=bind,readwrite,target=. ./iptables-wrapper-installer.sh --no-sanity-check

COPY --from=llvm-dist /usr/local/bin/clang /usr/local/bin/llc /usr/local/bin/

COPY --from=bpftool-dist /usr/local /usr/local

ARG BUILDPLATFORM
COPY --from=gops-cni-builder /out/${BUILDPLATFORM}/bin/loopback /cni/loopback
COPY --from=gops-cni-builder /out/${BUILDPLATFORM}/bin/gops /bin/gops

LABEL version="${VERSION}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

FROM ${TESTER_IMAGE} AS test

COPY --from=release / /

COPY --from=llvm-dist /test /test
COPY --from=llvm-dist /test /test
COPY --from=bpftool-dist /test /test
COPY --from=compilers /usr/bin/which /usr/bin/

RUN /test/bin/cst -C /test/llvm
RUN /test/bin/cst -C /test/bpftool
