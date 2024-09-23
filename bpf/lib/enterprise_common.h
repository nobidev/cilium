/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#if defined(ENABLE_EGRESS_GATEWAY_HA) && !defined(ENABLE_EGRESS_GATEWAY_COMMON)
#define ENABLE_EGRESS_GATEWAY_COMMON
#endif

struct egress_gw_ha_policy_key {
	struct bpf_lpm_trie_key lpm_key;
	__u32 saddr;
	__u32 daddr;
};

#define EGRESS_GW_HA_MAX_GATEWAY_NODES 64

struct egress_gw_ha_policy_entry {
	/* Size is the number of IPs set in the gateway_ips field (i.e. the number of
	 * gateways configured for the policy).
	 */
	__u32 size;
	__be32 egress_ip;
	__be32 gateway_ips[EGRESS_GW_HA_MAX_GATEWAY_NODES];
};

struct egress_gw_ha_policy_entry_v2 {
	struct egress_gw_ha_policy_entry policy;
	__u32 egress_ifindex;
};

struct egress_gw_ha_ct_entry {
	__be32 gateway_ip;
};

struct egress_gw_standalone_key {
	__be32 endpoint_ip;
};

struct egress_gw_standalone_entry {
	__be32 sec_identity;
	__be32 tunnel_endpoint;
};

#define ENCRYPTION_POLICY_FULL_PREFIX						\
  (8 * (sizeof(struct encryption_policy_key) - sizeof(struct bpf_lpm_trie_key)))

struct encryption_policy_key {
	struct bpf_lpm_trie_key lpm_key;
	__u32		src_sec_identity;
	__u32		dst_sec_identity;
	__be16		protocol; /* 16 bits are wasteful, but ran into prefix lookup issues due to struct packing, byte padding */
	__be16		port;
};

struct encryption_policy_entry {
	__u8	encrypt:1,
			pad:7;
};
