# Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Isovalent Inc and its suppliers, if any. The intellectual and technical
# concepts contained herein are proprietary to Isovalent Inc and its suppliers
# and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.  Dissemination of this information
# or reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Isovalent Inc.

ARG BASE_IMAGE=registry.redhat.io/ubi9/ubi-minimal
ARG UPSTREAM_IMAGE=quay.io/cilium/certgen:v0.2.3@sha256:cb3b1480f404489cbf0dbb9ac4576f44392532800180a4d6260ab430b4cbaedc

FROM ${UPSTREAM_IMAGE} AS upstream

FROM ${BASE_IMAGE}

LABEL name="Isovalent UBI certgen image" \
    maintainer="support@isovalent.com" \
    vendor="Isovalent" \
    release="1" \
    summary="Isovalent certgen image based on Red Hat Universal Base Image" \
    description="This image extends Red Hat UBI image with tooling for generating certificates" \
    org.opencontainers.image.authors="Isovalent" \
    org.opencontainers.image.url="https://isovalent.com" \
    org.opencontainers.image.documentation="https://isovalent.com/product" \
    org.opencontainers.image.vendor="Isovalent, part of Cisco" \
    org.opencontainers.image.title="Isovalent UBI cergen image" \
    org.opencontainers.image.description="This image extends Red Hat UBI image with tooling for generating certificates"
COPY LICENSE /usr/share/licenses/isovalent/
RUN ln -s /usr/share/licenses /licenses
COPY --from=upstream /usr/bin/cilium-certgen /usr/bin/cilium-certgen
ENTRYPOINT ["/usr/bin/cilium-certgen"]
