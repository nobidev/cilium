# Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Isovalent Inc and its suppliers, if any. The intellectual and technical
# concepts contained herein are proprietary to Isovalent Inc and its suppliers
# and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law. Dissemination of this information
# or reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Isovalent Inc.

FROM vmware/vcsim:v0.52.0@sha256:3d2924c88749abcd2965a41171faa8e583707d8fe38b6d1282fe4079df341fa0 AS vcsim

FROM vmware/govc:v0.52.0@sha256:cc1d61ab14266ab3c22d8752f796558dc0b5813db450a70b4529a87a91397a13 AS govc

FROM docker.io/library/alpine:3.23.2@sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62
COPY --from=vcsim /vcsim /usr/bin/vcsim
COPY --from=govc /govc /usr/bin/govc
