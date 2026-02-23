# Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Isovalent Inc and its suppliers, if any. The intellectual and technical
# concepts contained herein are proprietary to Isovalent Inc and its suppliers
# and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law. Dissemination of this information
# or reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Isovalent Inc.

FROM vmware/vcsim:v0.53.0@sha256:59b5164e17bb0b7bab2228fffb8473537b61fa7b5653f944365c44b69e0a9858 AS vcsim

FROM vmware/govc:v0.53.0@sha256:c8b440d1f20f4b92a1b658f1b49c0fcc86f0bd8a541c13b6f7c527193f70f886 AS govc

FROM docker.io/library/alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659
COPY --from=vcsim /vcsim /usr/bin/vcsim
COPY --from=govc /govc /usr/bin/govc
