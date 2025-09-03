#  Copyright (C) Isovalent, Inc. - All Rights Reserved. 
# 
#  NOTICE: All information contained herein is, and remains the property of 
#  Isovalent Inc and its suppliers, if any. The intellectual and technical 
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers 
#  and may be covered by U.S. and Foreign Patents, patents in process, and are 
#  protected by trade secret or copyright law.  Dissemination of this information 
#  or reproduction of this material is strictly forbidden unless prior written 
#  permission is obtained from Isovalent Inc.

ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:1732033893-de666b6@sha256:ee005bd47b20f78a727c06fdf2275861848be7acd242603c82f86ca8faaeda90
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:5a9c4852a21287686009bfe1cdc1fed6e7aabdea@sha256:188e398ee30456373530698d0d29de66dda0c4428068ea430027ceb7e9c15b7c
ARG CILIUM_RUNTIME_BASE_IMAGE=quay.io/isovalent/cilium-runtime-base-wfi:504064454acbefa61cca042b3908d4aae83298c9@sha256:b1e1eb766a330d913123d0a7ec2baa20fa3962cbb2958b1b5e8fd7b86b5859d1

FROM ${CILIUM_LLVM_IMAGE} AS llvm-dist
FROM ${CILIUM_BPFTOOL_IMAGE} AS bpftool-dist
FROM ${CILIUM_RUNTIME_BASE_IMAGE}

WORKDIR /go/src/github.com/cilium/cilium/enterprise/images/wolfi/runtime

RUN --mount=type=bind,readwrite,source=./images/runtime,target=. ./iptables-wrapper-installer.sh --no-sanity-check
RUN ln -s /run /var/run #TODO: move to apk package
RUN mkdir /cni
RUN ln -s /bin/loopback /cni/loopback

COPY --from=llvm-dist /usr/local/bin/clang /usr/local/bin/llc /usr/local/bin/
COPY --from=bpftool-dist /usr/local /usr/local
