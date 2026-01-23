/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "enterprise_config.h"

DECLARE_ENTERPRISE_CONFIG(bool, privnet_enable,
			  "True if the endpoint is in a non-default network")
DECLARE_ENTERPRISE_CONFIG(__u32, privnet_unknown_sec_id,
			  "The security identifier for unknown network traffic")
DECLARE_ENTERPRISE_CONFIG(__u16, privnet_network_id,
			  "The identifier of the private network")
DECLARE_ENTERPRISE_CONFIG(bool, privnet_bridge_enable,
			  "True if running on network bridge")

#ifdef IS_BPF_LXC
DECLARE_ENTERPRISE_CONFIG(union v6addr, privnet_ipv6,
			  "The endpoint's IPv6 address within the network")
#endif /* IS_BPF_LXC */
