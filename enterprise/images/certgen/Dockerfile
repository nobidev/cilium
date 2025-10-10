# Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Isovalent Inc and its suppliers, if any. The intellectual and technical
# concepts contained herein are proprietary to Isovalent Inc and its suppliers
# and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.  Dissemination of this information
# or reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Isovalent Inc.

ARG BASE_IMAGE=registry.redhat.io/ubi9/ubi-minimal:9.6@sha256:7c5495d5fad59aaee12abc3cbbd2b283818ee1e814b00dbc7f25bf2d14fa4f0c
ARG UPSTREAM_IMAGE=quay.io/cilium/certgen:v0.2.4@sha256:de7b97b1d19a34b674d0c4bc1da4db999f04ae355923a9a994ac3a81e1a1b5ff

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
ARG VERSION=0.0.0
LABEL version=${VERSION}

COPY LICENSE /usr/share/licenses/isovalent/
RUN ln -s /usr/share/licenses /licenses
COPY --from=upstream /usr/bin/cilium-certgen /usr/bin/cilium-certgen
ENTRYPOINT ["/usr/bin/cilium-certgen"]
