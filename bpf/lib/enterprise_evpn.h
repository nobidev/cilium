/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "socket.h"
#include "enterprise_config.h"

#ifndef EVPN_FIB_MAP_SIZE
#define EVPN_FIB_MAP_SIZE 65536
#endif

DECLARE_ENTERPRISE_CONFIG(bool, evpn_enable,
			  "True if evpn feature is enabled")
DECLARE_ENTERPRISE_CONFIG(__u32, evpn_device_ifindex,
			  "The interface index of the evpn vxlan device")
DECLARE_ENTERPRISE_CONFIG(union macaddr, evpn_device_mac,
			  "The mac address of the evpn vxlan device")

#define V4_EVPN_FIB_KEY_LEN (sizeof(__u32) * 8)
#define V6_EVPN_FIB_KEY_LEN (sizeof(union v6addr) * 8)

#define EVPN_FIB_STATIC_PREFIX					\
(8 * (sizeof(struct evpn_fib_key) - sizeof(struct bpf_lpm_trie_key)	\
- sizeof(union v6addr)))
#define EVPN_FIB_PREFIX_LEN(PREFIX) (EVPN_FIB_STATIC_PREFIX + (PREFIX))

struct evpn_fib_key {
	struct bpf_lpm_trie_key lpm_key;
	__u8 family;
	__u8 pad0;
	__u16 net_id;
	union {
		struct {
			__be32		ip4;
			__u32		pad1;
			__u32		pad2;
			__u32		pad3;
		};
		union v6addr	ip6;
	};
};

struct evpn_fib_val {
	__u32 vni;
	__u32 pad0;

	/* Remote VTEP MAC address (inner destination MAC) */
	union macaddr mac;

	/* Remote VTEP address (outer destination IP) */
	union {
		struct {
			__be32		ip4;
			__u32		pad1;
			__u32		pad2;
			__u32		pad3;
		};
		union v6addr	ip6;
	};
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct evpn_fib_key);
	__type(value, struct evpn_fib_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, EVPN_FIB_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_evpn_fib __section_maps_btf;

static __always_inline const struct evpn_fib_val *
evpn_fib_lookup4(__u16 net_id, __be32 addr)
{
	const struct evpn_fib_key key = {
		.lpm_key = { EVPN_FIB_PREFIX_LEN(V4_EVPN_FIB_KEY_LEN), {} },
		.family = AF_INET,
		.net_id = net_id,
		.ip4 = addr,
	};
	return map_lookup_elem(&cilium_evpn_fib, &key);
}

static __always_inline const struct evpn_fib_val *
evpn_fib_lookup6(__u16 net_id, const union v6addr *addr)
{
	const struct evpn_fib_key key = {
		.lpm_key = { EVPN_FIB_PREFIX_LEN(V6_EVPN_FIB_KEY_LEN), {} },
		.family = AF_INET6,
		.net_id = net_id,
		.ip6 = *addr,
	};
	return map_lookup_elem(&cilium_evpn_fib, &key);
}
