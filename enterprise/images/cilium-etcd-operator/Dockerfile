ARG BASE_IMAGE=registry.redhat.io/ubi9/ubi-micro:9.6@sha256:f5c5213d2969b7b11a6666fc4b849d56b48d9d7979b60a37bb853dff0255c14b

FROM docker.io/library/golang:1.25@sha256:a5e935dbd8bc3a5ea24388e376388c9a69b40628b6788a81658a801abbec8f2e AS builder
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
