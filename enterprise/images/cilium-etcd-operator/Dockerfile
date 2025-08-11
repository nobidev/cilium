ARG BASE_IMAGE=registry.redhat.io/ubi9/ubi-micro:9.6@sha256:647c02b5b6d4760b019a468ff620ec53009d8453679bee3b7e5a676499edb1c3

FROM docker.io/library/golang:1.24@sha256:ef5b4be1f94b36c90385abd9b6b4f201723ae28e71acacb76d00687333c17282 AS builder
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
