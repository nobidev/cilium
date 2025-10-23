/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/policy.h"
#include "lib/policy_log.h"

struct non_pinned_policy_map {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct policy_key);
	__type(value, struct policy_entry);
	__uint(max_entries, POLICY_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} __dummy_inner_ext_eps_policy__ __section_maps_btf;

/* Per-endpoint policy enforcement map */
struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, struct endpoint_key);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, EXT_EPS_POLICY_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
	__array(values, struct non_pinned_policy_map);
} cilium_ext_eps_policy __section_maps_btf;

static __always_inline int
__ext_eps_policy_can_access(struct __ctx_buff *ctx, struct endpoint_key *key,
			    __u32 sec_identity, __u16 ethertype, __be16 dport,
			    __u8 proto, int l4_off, __u8 *match_type, int dir,
			    bool is_untracked_fragment, __u8 *audited,
			    __s8 *ext_err, __u16 *proxy_port, __u32 *cookie)
{
	int ret;
	void *map;

	/* __policy_can_access uses local_id to output a debug message only,
	 * hence it is fine to pass a dummy value there.
	 */
	__u32 local_id = 0;

	map = map_lookup_elem(&cilium_ext_eps_policy, key);
	if (!map)
		return DROP_EP_NOT_READY;


	/* shouldn't this be set here instead? XXX: check with the normal path */
	*audited = 0;

	ret = __policy_can_access(map, ctx, local_id, sec_identity, ethertype, dport, proto,
				  l4_off, dir, is_untracked_fragment, match_type,
				  ext_err, proxy_port, cookie);
	if (ret >= 0)
		return ret;

	cilium_dbg(ctx, DBG_POLICY_DENIED, local_id, sec_identity);

#ifdef POLICY_AUDIT_MODE
	if (IS_ERR(ret)) {
		ret = CTX_ACT_OK;
		*audited = 1;
	}
#endif
	return ret;
}

#define EGRESS_POLICY	!!(CT_EGRESS)
#define INGRESS_POLICY	!(CT_EGRESS)

static __always_inline int
ext_eps_policy_can_egress4(struct __ctx_buff *ctx, __be32 ip, __u32 dst_id,
			   __be16 dport, __u8 proto, int l4_off, __u8 *match_type,
			   __u8 *audited, __s8 *ext_err, __u16 *proxy_port, __u32 *cookie)
{
	struct endpoint_key key = {
		.ip4 = ip,
		.family = ENDPOINT_KEY_IPV4,
	};

	return __ext_eps_policy_can_access(ctx, &key, dst_id, ETH_P_IP, dport, proto,
			l4_off, match_type, EGRESS_POLICY, false, audited, ext_err, proxy_port, cookie);
}

static __always_inline int
ext_eps_policy_can_ingress4(struct __ctx_buff *ctx, __be32 ip, __u32 dst_id,
			    __be16 dport, __u8 proto, int l4_off, bool is_untracked_fragment,
			    __u8 *match_type, __u8 *audited, __s8 *ext_err, __u16 *proxy_port, __u32 *cookie)
{
	struct endpoint_key key = {
		.ip4 = ip,
		.family = ENDPOINT_KEY_IPV4,
	};

	return __ext_eps_policy_can_access(ctx, &key, dst_id, ETH_P_IP, dport, proto,
			l4_off, match_type, INGRESS_POLICY, is_untracked_fragment, audited,
			ext_err, proxy_port, cookie);
}

static __always_inline int
ext_eps_policy_can_egress6(struct __ctx_buff *ctx, union v6addr ip6, __u32 dst_id,
			   __be16 dport, __u8 proto, int l4_off, __u8 *match_type,
			   __u8 *audited, __s8 *ext_err, __u16 *proxy_port, __u32 *cookie)
{
	struct endpoint_key key = {
		.ip6 = ip6,
		.family = ENDPOINT_KEY_IPV6,
	};

	return __ext_eps_policy_can_access(ctx, &key, dst_id, ETH_P_IP, dport, proto,
			l4_off, match_type, EGRESS_POLICY, false, audited, ext_err, proxy_port, cookie);
}

static __always_inline int
ext_eps_policy_can_ingress6(struct __ctx_buff *ctx, union v6addr ip6, __u32 dst_id,
			    __be16 dport, __u8 proto, int l4_off, bool is_untracked_fragment,
			    __u8 *match_type, __u8 *audited, __s8 *ext_err, __u16 *proxy_port, __u32 *cookie)
{
	struct endpoint_key key = {
		.ip6 = ip6,
		.family = ENDPOINT_KEY_IPV6,
	};

	return __ext_eps_policy_can_access(ctx, &key, dst_id, ETH_P_IP, dport, proto,
			l4_off, match_type, INGRESS_POLICY, is_untracked_fragment, audited,
			ext_err, proxy_port, cookie);
}
