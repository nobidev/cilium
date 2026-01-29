FROM registry.redhat.io/ubi9/ubi-minimal:9.6@sha256:34880b64c07f28f64d95737f82f891516de9a3b43583f39970f7bf8e4cfa48b7

LABEL name="Kubectl for Isovalent Networking for Kubernetes" \
      maintainer="support@isovalent.com" \
      vendor="Isovalent" \
      release="1" \
      summary="Kubectl for Isovalent Networking for Kubernetes" \
      description="Image of the Kubectl for Isovalent Networking for Kubernetes built on top of Red Hat Universal Base Image" \
      org.opencontainers.image.authors="Isovalent" \
      org.opencontainers.image.url="https://isovalent.com" \
      org.opencontainers.image.documentation="https://isovalent.com/product" \
      org.opencontainers.image.vendor="Isovalent, part of Cisco" \
      org.opencontainers.image.title="Isovalent Networking for Kubernetes Kubectl" \
      org.opencontainers.image.description="Image of the Kubectl for Isovalent Networking for Kubernetes built on top of Red Hat Universal Base Image" \
      io.k8s.description="Image of the Kubectl for Isovalent Networking for Kubernetes built on top of Red Hat Universal Base Image" \
      io.k8s.display-name="Kubectl for Isovalent Networking for Kubernetes"

LABEL org.opencontainers.image.created="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
ARG VERSION=0.0.0
LABEL version=${VERSION}

# renovate: datasource=github-releases depName=kubernetes/kubernetes
ARG KUBECTL_VERSION=v1.34.2
ARG TARGETARCH

# Install kubectl for the target architecture.
RUN set -euo pipefail; \
    curl -L -o /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl"; \
    chmod +x /usr/local/bin/kubectl

COPY LICENSE /usr/share/licenses/isovalent/
RUN ln -s /usr/share/licenses /licenses

CMD ["kubectl"]
