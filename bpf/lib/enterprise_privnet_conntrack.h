/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include "conntrack.h"
#include "conntrack_map.h"

#pragma once

/*
 * cilium_privnet_{ct4,ct6,ct_any4,ct_any6}_global are map of conntrack maps that
 * contains the connection tracking information of untranslated privnet flows.
 * Since IPs between different private networks can overlap, there is one
 * conntrack map per private network.
 */

 struct per_privnet_ct_map6_inner_map {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv6_ct_tuple);
	__type(value, struct ct_entry);
	__uint(max_entries, CT_MAP_SIZE_TCP);
	__uint(map_flags, LRU_MEM_FLAVOR);
 #ifndef BPF_TEST
 };
 #else
 } per_cluster_ct_tcp6_100 __section_maps_btf,
   per_cluster_ct_any6_100 __section_maps_btf;
 #endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, PRIVNET_CT_MAPS_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
	__array(values, struct per_privnet_ct_map6_inner_map);
#ifndef BPF_TEST
} cilium_privnet_ct6_global __section_maps_btf;
#else
} cilium_privnet_ct6_global __section_maps_btf = {
	.values = {
		[100] = &per_cluster_ct_tcp6_100,
	},
};
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, PRIVNET_CT_MAPS_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
	__array(values, struct per_privnet_ct_map6_inner_map);
#ifndef BPF_TEST
} cilium_privnet_ct_any6_global __section_maps_btf;
#else
} cilium_privnet_ct_any6_global __section_maps_btf = {
	.values = {
		[100] = &per_cluster_ct_any6_100,
	},
};
#endif

static __always_inline void *
privnet_get_ct_map6(const struct ipv6_ct_tuple *tuple, __u32 network_id)
{
	if (network_id != 0) {
		if (tuple->nexthdr == IPPROTO_TCP)
			return map_lookup_elem(&cilium_privnet_ct6_global, &network_id);

		return map_lookup_elem(&cilium_privnet_ct_any6_global, &network_id);
	}

	/* return default network CT map */
	return get_ct_map6(tuple);
}

static __always_inline void *
privnet_get_ct_any_map6(__u32 network_id)
{
	if (network_id != 0)
		return map_lookup_elem(&cilium_privnet_ct_any6_global, &network_id);

	/* return default network CT map */
	return &cilium_ct_any6_global;
}

 struct per_privnet_ct_map4_inner_map {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct ct_entry);
	__uint(max_entries, CT_MAP_SIZE_TCP);
	__uint(map_flags, LRU_MEM_FLAVOR);
 #ifndef BPF_TEST
 };
 #else
 } per_cluster_ct_tcp4_100 __section_maps_btf,
   per_cluster_ct_any4_100 __section_maps_btf;
 #endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, PRIVNET_CT_MAPS_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
	__array(values, struct per_privnet_ct_map4_inner_map);
#ifndef BPF_TEST
} cilium_privnet_ct4_global __section_maps_btf;
#else
} cilium_privnet_ct4_global __section_maps_btf = {
	.values = {
		[100] = &per_cluster_ct_tcp4_100,
	},
};
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, PRIVNET_CT_MAPS_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
	__array(values, struct per_privnet_ct_map4_inner_map);
#ifndef BPF_TEST
} cilium_privnet_ct_any4_global __section_maps_btf;
#else
} cilium_privnet_ct_any4_global __section_maps_btf = {
	.values = {
		[100] = &per_cluster_ct_any4_100,
	},
};
#endif

static __always_inline void *
privnet_get_ct_map4(const struct ipv4_ct_tuple *tuple, __u32 network_id)
{
	if (network_id != 0) {
		if (tuple->nexthdr == IPPROTO_TCP)
			return map_lookup_elem(&cilium_privnet_ct4_global, &network_id);

		return map_lookup_elem(&cilium_privnet_ct_any4_global, &network_id);
	}

	/* return default network CT map */
	return get_ct_map4(tuple);
}

static __always_inline void *
privnet_get_ct_any_map4(__u32 network_id)
{
	if (network_id != 0)
		return map_lookup_elem(&cilium_privnet_ct_any4_global, &network_id);

	/* return default network CT map */
	return &cilium_ct_any4_global;
}
