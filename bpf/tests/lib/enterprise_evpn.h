/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#define EVPN_FIB_V4_KEY(_net_id, _prefix, _prefix_len) { \
	.lpm_key.prefixlen = EVPN_FIB_PREFIX_LEN(_prefix_len), \
	.family = AF_INET, \
	.net_id = _net_id, \
	.ip4 = _prefix, \
}

static __always_inline void
evpn_fib_v4_add_nh4(__u16 net_id, __be32 prefix, __u32 prefix_len, __u32 vni,
		    union macaddr mac, __be32 nexthop)
{
	struct evpn_fib_key key = EVPN_FIB_V4_KEY(net_id, prefix, prefix_len);
	struct evpn_fib_val value = {
		.vni = vni,
		.family = AF_INET,
		.mac = mac,
		.ip4 = nexthop,
	};

	map_update_elem(&cilium_evpn_fib, &key, &value, BPF_ANY);
}

static __always_inline void
evpn_fib_v4_add_nh6(__u16 net_id, __be32 prefix, __u32 prefix_len, __u32 vni,
		    union macaddr mac, const union v6addr *nexthop)
{
	struct evpn_fib_key key = EVPN_FIB_V4_KEY(net_id, prefix, prefix_len);
	struct evpn_fib_val value = {
		.vni = vni,
		.family = AF_INET6,
		.mac = mac,
		.ip6 = *nexthop,
	};

	map_update_elem(&cilium_evpn_fib, &key, &value, BPF_ANY);
}

#define EVPN_FIB_V6_KEY(_net_id, _prefix, _prefix_len) { \
	.lpm_key.prefixlen = EVPN_FIB_PREFIX_LEN(_prefix_len), \
	.family = AF_INET6, \
	.net_id = _net_id, \
	.ip6 = *(_prefix), \
}

static __always_inline void
evpn_fib_v6_add_nh6(__u16 net_id, const union v6addr *prefix, __u32 prefix_len,
		    __u32 vni, union macaddr mac, const union v6addr *nexthop)
{
	struct evpn_fib_key key = EVPN_FIB_V6_KEY(net_id, prefix, prefix_len);
	struct evpn_fib_val value = {
		.vni = vni,
		.family = AF_INET6,
		.mac = mac,
		.ip6 = *nexthop,
	};

	map_update_elem(&cilium_evpn_fib, &key, &value, BPF_ANY);
}

static __always_inline void
evpn_fib_v6_add_nh4(__u16 net_id, const union v6addr *prefix, __u32 prefix_len,
		    __u32 vni, union macaddr mac, __be32 nexthop)
{
	struct evpn_fib_key key = EVPN_FIB_V6_KEY(net_id, prefix, prefix_len);
	struct evpn_fib_val value = {
		.vni = vni,
		.family = AF_INET,
		.mac = mac,
		.ip4 = nexthop,
	};

	map_update_elem(&cilium_evpn_fib, &key, &value, BPF_ANY);
}

static __always_inline void
evpn_fib_v4_del(__u16 net_id, __be32 prefix, __u32 prefix_len)
{
	struct evpn_fib_key key = {
		.lpm_key.prefixlen = EVPN_FIB_PREFIX_LEN(prefix_len),
		.family = AF_INET,
		.net_id = net_id,
		.ip4 = prefix,
	};

	map_delete_elem(&cilium_evpn_fib, &key);
}

static __always_inline void
evpn_fib_v6_del(__u16 net_id, const union v6addr *prefix, __u32 prefix_len)
{
	struct evpn_fib_key key = {
		.lpm_key.prefixlen = EVPN_FIB_PREFIX_LEN(prefix_len),
		.family = AF_INET6,
		.net_id = net_id,
		.ip6 = *prefix,
	};

	map_delete_elem(&cilium_evpn_fib, &key);
}
