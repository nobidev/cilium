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

FROM docker.io/library/alpine:3.22.2@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412
COPY --from=vcsim /vcsim /usr/bin/vcsim
COPY --from=govc /govc /usr/bin/govc
