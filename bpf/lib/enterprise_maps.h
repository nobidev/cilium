/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#ifndef SKIP_POLICY_MAP
#ifdef CILIUM_MESH_POLICY_MAP
struct non_pinned_policy_map {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct policy_key);
	__type(value, struct policy_entry);
	__uint(max_entries, POLICY_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} __dummy_inner_cilium_mesh_policy_map__ __section_maps_btf;

/* Per-endpoint policy enforcement map for Cilium Mesh */
struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, struct endpoint_key);
	__type(value, int);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_MESH_POLICY_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
	__array(values, struct non_pinned_policy_map);
} CILIUM_MESH_POLICY_MAP __section_maps_btf;
#endif
#endif

#ifdef LB_FLOW_LOGS_ENABLED
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, CILIUM_LB_FLOW_LOG_RB_MAP_SIZE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} CILIUM_LB_FLOW_LOG_RB_V4_MAP __section_maps_btf;
#endif /* LB_FLOW_LOGS_ENABLED */
