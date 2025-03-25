ARG BASE_IMAGE=quay.io/isovalent/clustermesh-apiserver:stage_1

FROM ${BASE_IMAGE} AS release

LABEL name="Cluster Mesh API server component of Isovalent Networking for Kubernetes" \
      maintainer="support@isovalent.com" \
      vendor="Isovalent" \
      release="1" \
      summary="Cluster Mesh API server component of Isovalent Networking for Kubernetes" \
      description="Image of the Cluster Mesh API server component of Isovalent Networking for Kubernetes built on top of Red Hat Universal Base Image" \
      org.opencontainers.image.authors="Isovalent" \
      org.opencontainers.image.url="https://isovalent.com" \
      org.opencontainers.image.documentation="https://isovalent.com/product" \
      org.opencontainers.image.vendor="Isovalent, part of Cisco" \
      org.opencontainers.image.title="Isovalent Networking for Kubernetes Cluster Mesh API server image" \
      org.opencontainers.image.description="Image of the Cluster Mesh API server component of Isovalent Networking for Kubernetes built on top of Red Hat Universal Base Image" \
      io.k8s.description="Image of the Cluster Mesh API server component of Isovalent Networking for Kubernetes built on top of Red Hat Universal Base Image" \
      io.k8s.display-name="Cluster Mesh API server component of Isovalent Networking for Kubernetes"

ARG BUILD_DATE
LABEL org.opencontainers.image.created="${BUILD_DATE}"

COPY LICENSE /usr/share/licenses/isovalent/
RUN mv LICENSE.all /usr/share/licenses/isovalent/LICENSE.dependencies && ln -s /usr/share/licenses /licenses
# use uid:gid for the nonroot user for compatibility with runAsNonRoot
USER 65532:65532
