# Copyright (C) Isovalent, Inc. - All Rights Reserved.

ARG TESTER_IMAGE=quay.io/cilium/image-tester:0a7ee27812441d95926aec83929d97e93ce96aae@sha256:e96542b4f71dbc9cbe77feaf5b1fa9bd5e13122ee6418094731212f1c5667c67
ARG UBI_MINI_IMAGE=registry.redhat.io/ubi9/ubi-minimal:9.6@sha256:7c5495d5fad59aaee12abc3cbbd2b283818ee1e814b00dbc7f25bf2d14fa4f0c
ARG GOLANG_IMAGE=docker.io/library/golang:1.25.3@sha256:6ea52a02734dd15e943286b048278da1e04eca196a564578d718c7720433dbbe
ARG CILIUM_LLVM_IMAGE=quay.io/isovalent-dev/cilium-llvm-ubi:1754712783-48bbfc6@sha256:b673ca26acfc574d815c231814707ffa6e39e039450ce95bf296a436f4ff22e9
ARG CILIUM_BPFTOOL_IMAGE=quay.io/isovalent-dev/cilium-bpftool-ubi:1754712783-48bbfc6@sha256:e4401c2a3bbbacbf6a061ce8294165d03779ae9a904e7902303d4d0b8c9f9360
ARG COMPILERS_IMAGE=quay.io/isovalent-dev/image-compilers-ubi:1754570895-16e2939@sha256:731c9cebd0d6bd5846faa6cf76d0e7841f700df745a9f814273e77c5ae43121a

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
