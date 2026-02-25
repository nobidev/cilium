/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "enterprise_config.h"

DECLARE_ENTERPRISE_CONFIG(bool, evpn_enable,
			  "True if evpn feature is enabled")
DECLARE_ENTERPRISE_CONFIG(__u32, evpn_device_ifindex,
			  "The interface index of the evpn vxlan device")
DECLARE_ENTERPRISE_CONFIG(union macaddr, evpn_device_mac,
			  "The mac address of the evpn vxlan device")
