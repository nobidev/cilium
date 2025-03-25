# Copyright (C) Isovalent, Inc. - All Rights Reserved.

ARG UPSTREAM_IMAGE
ARG BASE_IMAGE

FROM ${UPSTREAM_IMAGE} as cilium-envoy

FROM ${BASE_IMAGE}

LABEL name="Cilium Envoy proxy for Isovalent Networking for Kubernetes with minimal Envoy extensions and Cilium policy enforcement filters" \
      maintainer="support@isovalent.com" \
      vendor="Isovalent" \
      release="1" \
      summary="Cilium Envoy proxy for Isovalent Networking for Kubernetes with minimal Envoy extensions and Cilium policy enforcement filters" \
      description="Image of the Cilium Envoy proxy for Isovalent Networking for Kubernetes with minimal Envoy extensions and Cilium policy enforcement filters built on top of Red Hat Universal Base Image" \
      org.opencontainers.image.authors="Isovalent" \
      org.opencontainers.image.url="https://isovalent.com" \
      org.opencontainers.image.documentation="https://isovalent.com/product" \
      org.opencontainers.image.vendor="Isovalent, part of Cisco" \
      org.opencontainers.image.title="Isovalent Networking for Kubernetes Cilium Envoy proxy image" \
      org.opencontainers.image.description="Image of the Cilium Envoy proxy for Isovalent Networking for Kubernetes with minimal Envoy extensions and Cilium policy enforcement filters built on top of Red Hat Universal Base Image" \
      io.k8s.description="Image of the Cilium Envoy proxy for Isovalent Networking for Kubernetes with minimal Envoy extensions and Cilium policy enforcement filters built on top of Red Hat Universal Base Image" \
      io.k8s.display-name="Cilium Envoy proxy component of Isovalent Networking for Kubernetes"

LABEL org.opencontainers.image.created="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
ARG VERSION=0.0.0
LABEL version=${VERSION}

COPY LICENSE /usr/share/licenses/isovalent/
RUN ln -s /usr/share/licenses /licenses

COPY --from=cilium-envoy /usr/lib/libcilium.so /usr/lib64/libcilium.so
COPY --from=cilium-envoy /usr/lib/libcilium.so /usr/lib/libcilium.so

COPY --from=cilium-envoy /usr/bin/cilium-envoy /usr/bin/cilium-envoy-starter /usr/bin/
