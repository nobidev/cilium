/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#if defined(ENABLE_EGRESS_GATEWAY_HA) && !defined(ENABLE_EGRESS_GATEWAY_COMMON)
#define ENABLE_EGRESS_GATEWAY_COMMON
#endif
