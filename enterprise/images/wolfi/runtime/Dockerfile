#  Copyright (C) Isovalent, Inc. - All Rights Reserved. 
# 
#  NOTICE: All information contained herein is, and remains the property of 
#  Isovalent Inc and its suppliers, if any. The intellectual and technical 
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers 
#  and may be covered by U.S. and Foreign Patents, patents in process, and are 
#  protected by trade secret or copyright law.  Dissemination of this information 
#  or reproduction of this material is strictly forbidden unless prior written 
#  permission is obtained from Isovalent Inc.

ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:9f1bfe736009afb1fbb562718bbc42ea07d37d8e@sha256:a666a7a01a2dc610c3ab6e32f25ca5e294201f3cbbc01f233320c527955deee3
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:0db3a73729ceb42e947d826bb96a655be79e5317@sha256:de23c9546c4eafab33f75d6f5d129947bbbafc132dbd113c0cecc9a61929e6b0
ARG CILIUM_RUNTIME_BASE_IMAGE=quay.io/isovalent/cilium-runtime-base-wfi:1c6989d9693f4ee838dfe4f6f8af93e23be1ec38@sha256:eb3c636f83dbc85dc70db0265265e4ff253a78e855b8a731b67615e7e4abe85c

FROM ${CILIUM_LLVM_IMAGE} AS llvm-dist
FROM ${CILIUM_BPFTOOL_IMAGE} AS bpftool-dist

FROM ${CILIUM_RUNTIME_BASE_IMAGE}

WORKDIR /go/src/github.com/cilium/cilium/enterprise/images/wolfi/runtime
RUN --mount=type=bind,readwrite,source=./images/runtime,target=. \
 ./iptables-wrapper-installer.sh --no-sanity-check
RUN ln -s /run /var/run #TODO: move to apk package

COPY --from=llvm-dist /usr/local/bin/clang /usr/local/bin/llc /usr/local/bin/
COPY --from=bpftool-dist /usr/local /usr/local
