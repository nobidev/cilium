/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

static __always_inline void
__privnet_fib_v4_add_entry(__u16 net_id, __be32 prefix, __be32 nexthop,
			   bool is_subnet_route, bool is_static_route,
			   bool l2_announce)
{
	struct privnet_fib_key key = {
		.lpm_key.prefixlen = PRIVNET_FIB_PREFIX_LEN(V4_PRIVNET_KEY_LEN),
		.net_id = net_id,
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = prefix,
	};
	struct privnet_fib_val value = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = nexthop,
		.flag_is_static_route = is_static_route,
		.flag_is_subnet_route = is_subnet_route,
		.flag_l2_announce = l2_announce,
	};

	map_update_elem(&cilium_privnet_fib, &key, &value, BPF_ANY);
}

static __always_inline void
__privnet_fib_v4_del_entry(__u16 net_id, __be32 prefix)
{
	struct privnet_fib_key key = {
		.lpm_key.prefixlen = PRIVNET_FIB_PREFIX_LEN(V4_PRIVNET_KEY_LEN),
		.net_id = net_id,
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = prefix,
	};

	map_delete_elem(&cilium_privnet_fib, &key);
}

static __always_inline void
__privnet_fib_v6_add_entry(__u16 net_id, const union v6addr *prefix, const union v6addr *nexthop,
			   bool is_subnet_route, bool is_static_route,
			   bool l2_announce)
{
	struct privnet_fib_key key = {
		.lpm_key.prefixlen = PRIVNET_FIB_PREFIX_LEN(V6_PRIVNET_KEY_LEN),
		.net_id = net_id,
		.family = ENDPOINT_KEY_IPV6,
	};
	struct privnet_fib_val value = {
		.family = ENDPOINT_KEY_IPV6,
		.flag_is_static_route = is_static_route,
		.flag_is_subnet_route = is_subnet_route,
		.flag_l2_announce = l2_announce,
	};

	__bpf_memcpy_builtin(&key.ip6, prefix, sizeof(*prefix));
	__bpf_memcpy_builtin(&value.ip6, nexthop, sizeof(*nexthop));

	map_update_elem(&cilium_privnet_fib, &key, &value, BPF_ANY);
}

static __always_inline void
__privnet_fib_v6_del_entry(__u16 net_id, const union v6addr *prefix)
{
	struct privnet_fib_key key = {
		.lpm_key.prefixlen = PRIVNET_FIB_PREFIX_LEN(V6_PRIVNET_KEY_LEN),
		.net_id = net_id,
		.family = ENDPOINT_KEY_IPV6,
	};
	__bpf_memcpy_builtin(&key.ip6, prefix, sizeof(*prefix));

	map_delete_elem(&cilium_privnet_fib, &key);
}

static __always_inline void
__privnet_pip_v4_add_entry(__be32 pod_ip, __u16 net_id, __be32 net_ip)
{
	struct privnet_pip_key key = {
		.lpm_key.prefixlen = PRIVNET_PIP_PREFIX_LEN(V4_PRIVNET_KEY_LEN),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = pod_ip,
	};

	struct privnet_pip_val value = {
		.family = ENDPOINT_KEY_IPV4,
		.net_id = net_id,
		.ip4 = net_ip,
		.ifindex = 1, /* hardcoded ifindex for pips */
	};
	/* hardcoded mac for pips */
	value.mac = (union macaddr){ .addr = mac_two_addr};

	map_update_elem(&cilium_privnet_pip, &key, &value, BPF_ANY);
}

static __always_inline void
__privnet_pip_v4_del_entry(__be32 pod_ip)
{
	struct privnet_pip_key key = {
		.lpm_key.prefixlen = PRIVNET_PIP_PREFIX_LEN(V4_PRIVNET_KEY_LEN),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = pod_ip,
	};

	map_delete_elem(&cilium_privnet_pip, &key);
}

static __always_inline void
__privnet_pip_v6_add_entry(const union v6addr *pod_ip, const union v6addr *net_ip, __be16 net_id)
{
	struct privnet_pip_key key = {
		.lpm_key.prefixlen = PRIVNET_PIP_PREFIX_LEN(V6_PRIVNET_KEY_LEN),
		.family = ENDPOINT_KEY_IPV6,
	};
	struct privnet_pip_val value = {
		.family = ENDPOINT_KEY_IPV6,
		.net_id = net_id,
	};

	memcpy(&key.ip6, pod_ip, sizeof(*pod_ip));
	memcpy(&value.ip6, net_ip, sizeof(*net_ip));

	map_update_elem(&cilium_privnet_pip, &key, &value, BPF_ANY);
}

static __always_inline void
__privnet_pip_v6_del_entry(const union v6addr *pod_ip)
{
	struct privnet_pip_key key = {
		.lpm_key.prefixlen = PRIVNET_PIP_PREFIX_LEN(V6_PRIVNET_KEY_LEN),
		.family = ENDPOINT_KEY_IPV6,
	};
	memcpy(&key.ip6, pod_ip, sizeof(*pod_ip));

	map_delete_elem(&cilium_privnet_pip, &key);
}

static __always_inline void
privnet_v4_add_endpoint_entry(__u16 net_id, __be32 net_ip, __be32 pod_ip)
{
	__privnet_fib_v4_add_entry(net_id, net_ip, pod_ip, false, false, true);
	__privnet_pip_v4_add_entry(pod_ip, net_id, net_ip);
}

static __always_inline void
privnet_v4_del_endpoint_entry(__u16 net_id, __be32 net_ip, __be32 pod_ip)
{
	__privnet_fib_v4_del_entry(net_id, net_ip);
	__privnet_pip_v4_del_entry(pod_ip);
}

static __always_inline void
privnet_v4_add_subnet_route(__u16 net_id, __be32 prefix, __be32 nexthop)
{
	__privnet_fib_v4_add_entry(net_id, prefix, nexthop, true, false, false);
}

static __always_inline void
privnet_v4_add_static_route(__u16 net_id, __be32 prefix, __be32 nexthop)
{
	__privnet_fib_v4_add_entry(net_id, prefix, nexthop, false, true, false);
}

static __always_inline void
privnet_v4_del_route(__u16 net_id, __be32 prefix)
{
	__privnet_fib_v4_del_entry(net_id, prefix);
}

static __always_inline void
privnet_v6_add_endpoint_entry(__u16 net_id, const union v6addr *net_ip, const union v6addr *pod_ip)
{
	__privnet_fib_v6_add_entry(net_id, net_ip, pod_ip, false, false, true);
	__privnet_pip_v6_add_entry(pod_ip, net_ip, net_id);
}

static __always_inline void
privnet_v6_del_endpoint_entry(__u16 net_id, const union v6addr *net_ip, const union v6addr *pod_ip)
{
	__privnet_fib_v6_del_entry(net_id, net_ip);
	__privnet_pip_v6_del_entry(pod_ip);
}

static __always_inline void
privnet_v6_add_subnet_route(__u16 net_id, const union v6addr *prefix, const union v6addr *nexthop)
{
	__privnet_fib_v6_add_entry(net_id, prefix, nexthop, true, false, false);
}

static __always_inline void
privnet_v6_add_static_route(__u16 net_id, const union v6addr *prefix, const union v6addr *nexthop)
{
	__privnet_fib_v6_add_entry(net_id, prefix, nexthop, false, true, false);
}

static __always_inline void
privnet_v6_del_route(__u16 net_id, const union v6addr *prefix)
{
	__privnet_fib_v6_del_entry(net_id, prefix);
}
