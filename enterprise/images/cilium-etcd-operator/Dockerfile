ARG BASE_IMAGE=registry.redhat.io/ubi9/ubi-micro@sha256:839f16991579b023d4452eadd0efa925e438f8b73063afe4f75bdc6cf7a09b12

FROM docker.io/library/golang:1.13@sha256:8ebb6d5a48deef738381b56b1d4cd33d99a5d608e0d03c5fe8dfa3f68d41a1f8 AS builder
ADD . /go/src/github.com/cilium/cilium-etcd-operator
WORKDIR /go/src/github.com/cilium/cilium-etcd-operator
RUN make cilium-etcd-operator
RUN strip cilium-etcd-operator


FROM ${BASE_IMAGE}

LABEL name="Cilium etcd operator" \
      maintainer="support@isovalent.com" \
      vendor="Isovalent" \
      release="1" \
      summary="Cilium etcd operator" \
      description="Image of the Cilium etcd operator" \
      org.opencontainers.image.authors="Isovalent" \
      org.opencontainers.image.url="https://isovalent.com" \
      org.opencontainers.image.documentation="https://isovalent.com/product" \
      org.opencontainers.image.vendor="Isovalent, part of Cisco" \
      org.opencontainers.image.title="Isovalent Networking for Kubernetes Cilium etcd operator image" \
      org.opencontainers.image.description="Image of the Cilium etcd operator for Isovalent Networking for Kubernetes built on top of Red Hat Universal Base Image" \
      io.k8s.description="Image of the Cilium etcd operator for Isovalent Networking for Kubernetes built on top of Red Hat Universal Base Image" \
      io.k8s.display-name="Cilium etcd operator component of Isovalent Networking for Kubernetes"

LABEL org.opencontainers.image.created="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

COPY LICENSE /usr/share/licenses/isovalent/
COPY --from=builder /go/src/github.com/cilium/cilium-etcd-operator/cilium-etcd-operator /usr/bin/cilium-etcd-operator
WORKDIR /
CMD ["/usr/bin/cilium-etcd-operator"]