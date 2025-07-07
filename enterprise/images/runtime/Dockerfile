# Copyright (C) Isovalent, Inc. - All Rights Reserved.

ARG TESTER_IMAGE=quay.io/cilium/image-tester:0a7ee27812441d95926aec83929d97e93ce96aae@sha256:e96542b4f71dbc9cbe77feaf5b1fa9bd5e13122ee6418094731212f1c5667c67
ARG UBI_MINI_IMAGE=registry.redhat.io/ubi9/ubi-minimal@sha256:f172b3082a3d1bbe789a1057f03883c1113243564f01cd3020e27548b911d3f8
ARG GOLANG_IMAGE=docker.io/library/golang:1.24.4@sha256:20a022e5112a144aa7b7aeb3f22ebf2cdaefcc4aac0d64e8deeee8cdc18b9c0f
ARG CILIUM_LLVM_IMAGE=quay.io/isovalent-dev/cilium-llvm-ubi:1741958010-f42ddd2@sha256:1467aec609f6964167b861d4ccb7e3480b8ed9d39351cb2e3b375fca81127c5d
ARG CILIUM_BPFTOOL_IMAGE=quay.io/isovalent-dev/cilium-bpftool-ubi:1741958010-f42ddd2@sha256:7ad5f9ad2ae6ebe05bf32b69dd493a0ea3fad614c0a0760cb948bd4c6ea20ace
ARG COMPILERS_IMAGE=quay.io/isovalent-dev/image-compilers-ubi:1741861540-21b4a3b@sha256:759bb175d499da0d8fe95479484f80e58a5737473cc6b9aa7a69e2603a75f09b

ARG VERSION=0.0.0-dev
ARG REVISION=000000

FROM ${CILIUM_LLVM_IMAGE} AS llvm-dist
FROM ${CILIUM_BPFTOOL_IMAGE} AS bpftool-dist
FROM ${COMPILERS_IMAGE} AS compilers

FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} AS gops-cni-builder

RUN apt-get update && apt-get install -y binutils-aarch64-linux-gnu binutils-x86-64-linux-gnu

# build-gops.sh will build both archs at the same time
WORKDIR /go/src/github.com/isovalent/cilium/images/runtime
RUN --mount=type=bind,readwrite,source=./images/runtime,target=. --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
    ./build-gops.sh
# download-cni.sh will build both archs at the same time
RUN --mount=type=bind,readwrite,source=./images/runtime,target=. --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
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

WORKDIR /go/src/github.com/isovalent/cilium/enterprise/images/runtime
RUN --mount=type=bind,readwrite,source=./enterprise/images/runtime,target=. ./install-runtime-deps.sh
COPY ./enterprise/images/runtime/LICENSE /usr/share/licenses/isovalent/
RUN ln -s /usr/share/licenses /licenses

WORKDIR /go/src/github.com/isovalent/cilium/images/runtime
RUN --mount=type=bind,readwrite,source=./images/runtime,target=. ./iptables-wrapper-installer.sh --no-sanity-check

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
