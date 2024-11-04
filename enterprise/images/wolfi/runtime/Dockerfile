# Copyright Isovalent
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:9f1bfe736009afb1fbb562718bbc42ea07d37d8e@sha256:a666a7a01a2dc610c3ab6e32f25ca5e294201f3cbbc01f233320c527955deee3
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:0db3a73729ceb42e947d826bb96a655be79e5317@sha256:de23c9546c4eafab33f75d6f5d129947bbbafc132dbd113c0cecc9a61929e6b0

FROM ${CILIUM_LLVM_IMAGE} AS llvm-dist
FROM ${CILIUM_BPFTOOL_IMAGE} AS bpftool-dist

FROM quay.io/isovalent/cilium-runtime-base@sha256:33e375d8f45b4536f007415d5fb4ac4a35c5776930ea90f7e65ef39da47e26fb

WORKDIR /go/src/github.com/cilium/cilium/enterprise/images/wolfi/runtime
RUN --mount=type=bind,readwrite,source=./images/runtime,target=. \
 ./iptables-wrapper-installer.sh --no-sanity-check
RUN ln -s /run /var/run #TODO: move to apk package

COPY --from=llvm-dist /usr/local/bin/clang /usr/local/bin/llc /usr/local/bin/
COPY --from=bpftool-dist /usr/local /usr/local
