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
ARG CILIUM_RUNTIME_BASE_IMAGE=quay.io/isovalent/cilium-runtime-base-wfi:a5a2560eacfaafc032bfa4294603344f4fc70ca2@sha256:e454003d3e5a03416d78044341e0f8406e64e7cde029e5a5ef7367bd9bf270a3
ARG CILIUM_IPTABLES_IMAGE=quay.io/cilium/iptables:1331e9b1b03f70c9d8b08626d9a7126963f86478@sha256:d761d967243aced2729adde1e332a9c9def6baeb61f5f6cde5758b04e9a79355

FROM ${CILIUM_LLVM_IMAGE} AS llvm-dist
FROM ${CILIUM_BPFTOOL_IMAGE} AS bpftool-dist
FROM ${CILIUM_IPTABLES_IMAGE} AS iptables-dist

RUN apt-get update
RUN apt-get -y install wget
RUN wget https://www.netfilter.org/projects/iptables/files/iptables-1.8.8.tar.bz2 && \
    wget https://www.netfilter.org/projects/iptables/files/iptables-1.8.8.tar.bz2.sha256sum && \
    sha256sum --check iptables-1.8.8.tar.bz2.sha256sum

FROM ${CILIUM_RUNTIME_BASE_IMAGE}

WORKDIR /go/src/github.com/cilium/cilium/enterprise/images/wolfi/runtime

COPY --from=iptables-dist /iptables/iptables-1.8.8.tar.bz2 /iptables/iptables-1.8.8.tar.bz2
# Needed for iptables configure script to use gcc with no issue 
RUN ln -s /usr/bin/gcc-11 /usr/bin/gcc
# Installation of iptables v1.8.8
RUN cd /iptables && tar -xvf iptables-1.8.8.tar.bz2 
RUN cd /iptables/iptables-1.8.8 && ./configure --sbindir=/sbin && make && make install

RUN --mount=type=bind,readwrite,source=./images/runtime,target=. ./iptables-wrapper-installer.sh --no-sanity-check
RUN ln -s /run /var/run #TODO: move to apk package
RUN mkdir /cni
RUN ln -s /bin/loopback /cni/loopback

COPY --from=llvm-dist /usr/local/bin/clang /usr/local/bin/llc /usr/local/bin/
COPY --from=bpftool-dist /usr/local /usr/local
