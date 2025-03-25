ARG BASE_IMAGE=quay.io/isovalent/operator:stage_1

FROM ${BASE_IMAGE} AS release

LABEL name="Operator component of Isovalent Networking for Kubernetes" \
      maintainer="support@isovalent.com" \
      vendor="Isovalent" \
      release="1" \
      summary="Operator component of Isovalent Networking for Kubernetes" \
      description="Image of the operator component of Isovalent Networking for Kubernetes built on top of Red Hat Universal Base Image" \
      org.opencontainers.image.authors="Isovalent" \
      org.opencontainers.image.url="https://isovalent.com" \
      org.opencontainers.image.documentation="https://isovalent.com/product" \
      org.opencontainers.image.vendor="Isovalent, part of Cisco" \
      org.opencontainers.image.title="Isovalent Networking for Kubernetes operator image" \
      org.opencontainers.image.description="Image of the operator component of Isovalent Networking for Kubernetes built on top of Red Hat Universal Base Image" \
      io.k8s.description="Image of the operator component of Isovalent Networking for Kubernetes built on top of Red Hat Universal Base Image" \
      io.k8s.display-name="Operator component of Isovalent Networking for Kubernetes"

ARG BUILD_DATE
LABEL org.opencontainers.image.created="${BUILD_DATE}"
ARG VERSION=0.0.0
LABEL version=${VERSION}

COPY LICENSE /usr/share/licenses/isovalent/
RUN mv LICENSE.all /usr/share/licenses/isovalent/LICENSE.dependencies && ln -s /usr/share/licenses /licenses
