# Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Isovalent Inc and its suppliers, if any. The intellectual and technical
# concepts contained herein are proprietary to Isovalent Inc and its suppliers
# and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.  Dissemination of this information
# or reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Isovalent Inc.

# based on https://github.com/cilium/image-tools/blob/master/images/startup-script/Dockerfile

ARG BASE_IMAGE=registry.redhat.io/ubi9/ubi-minimal:9.6@sha256:34880b64c07f28f64d95737f82f891516de9a3b43583f39970f7bf8e4cfa48b7
ARG UPSTREAM_VERSION=c54c7edeab7fde4da68e59acd319ab24af242c3f@sha256:8d7b41c4ca45860254b3c19e20210462ef89479bb6331d6760c4e609d651b29c

FROM quay.io/cilium/startup-script:${UPSTREAM_VERSION} AS manage-script-getter

FROM ${BASE_IMAGE}

LABEL name="Isovalent UBI startup image" \
    maintainer="support@isovalent.com" \
    vendor="Isovalent" \
    release="1" \
    summary="Isovalent startup script image based on Red Hat Universal Base Image" \
    description="This image extends Red Hat UBI image with generic tooling used by Isovalent images" \
    org.opencontainers.image.authors="Isovalent" \
    org.opencontainers.image.url="https://isovalent.com" \
    org.opencontainers.image.documentation="https://isovalent.com/product" \
    org.opencontainers.image.vendor="Isovalent, part of Cisco" \
    org.opencontainers.image.title="Isovalent UBI startup image" \
    org.opencontainers.image.description="This image extends Red Hat UBI image with generic tooling used by Isovalent images"
ARG VERSION=0.0.0
LABEL version=${VERSION}

COPY LICENSE /usr/share/licenses/isovalent/
RUN ln -s /usr/share/licenses /licenses

WORKDIR /go/src/github.com/isovalent/cilium/enterprise/images/runtime
RUN --mount=type=bind,readwrite,target=. ./install-deps.sh
COPY --from=manage-script-getter /usr/bin/manage-startup-script.sh /usr/bin/
RUN chmod +x /usr/bin/manage-startup-script.sh
CMD [ "/usr/bin/manage-startup-script.sh" ]
