/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

DECLARE_CONFIG(__u32, privnet_ipv4,
	       "The endpoint's IPv4 address within the network")
DECLARE_CONFIG(union v6addr, privnet_ipv6,
	       "The endpoint's IPv6 address within the network")
DECLARE_CONFIG(union macaddr, privnet_mac,
	       "The MAC address of the endpoint's interface within the network")
