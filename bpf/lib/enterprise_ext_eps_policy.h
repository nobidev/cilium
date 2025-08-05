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
	__type(value, int);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, EXT_EPS_POLICY_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
	__array(values, struct non_pinned_policy_map);
} cilium_ext_eps_policy __section_maps_btf;

static __always_inline void *ext_eps_policy_map(__u32 ip __maybe_unused)
{
	struct endpoint_key key = {};

	key.ip4 = ip;
	key.family = ENDPOINT_KEY_IPV4;

	return map_lookup_elem(&cilium_ext_eps_policy, &key);
}

static __always_inline int
__ext_eps_policy_can_access(struct __ctx_buff *ctx, __be32 ip, __u32 sec_identity,
			    __be16 dport, __u8 proto, int l4_off, __u8 *match_type, int dir,
			    __u8 *audited, __s8 *ext_err, __u16 *proxy_port)
{
	int ret;
	void *map;
	__u32 local_id = 0; /* XXX */
	bool is_untracked_fragment = false; /* XXX */
	__u16 ethertype = ETH_P_IP; /* XXX */

	map = ext_eps_policy_map(ip);
	if (!map)
		return CTX_ACT_OK; /* XXX ? actually, isn't this a fatal error? need to report somehow */

	/* shouldn't this be set here instead? XXX: check with the normal path */
	*audited = 0;

	ret = __policy_can_access(map, ctx, local_id, sec_identity, ethertype, dport, proto,
				  l4_off, dir, is_untracked_fragment, match_type,
				  ext_err, proxy_port);
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
			   __u8 *audited, __s8 *ext_err, __u16 *proxy_port)
{
	return __ext_eps_policy_can_access(ctx, ip, dst_id, dport, proto, l4_off,
			match_type, EGRESS_POLICY, audited, ext_err, proxy_port);
}

static __always_inline int
ext_eps_policy_can_ingress4(struct __ctx_buff *ctx, __be32 ip, __u32 dst_id,
			    __be16 dport, __u8 proto, int l4_off, __u8 *match_type,
			    __u8 *audited, __s8 *ext_err, __u16 *proxy_port)
{
	return __ext_eps_policy_can_access(ctx, ip, dst_id, dport, proto, l4_off,
			match_type, INGRESS_POLICY, audited, ext_err, proxy_port);
}
