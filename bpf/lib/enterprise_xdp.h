/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (C) Isovalent, Inc. - All Rights Reserved. */

#pragma once

#ifdef LB_FLOW_LOGS_ENABLED
#ifdef ENABLE_IPV4
/* Format must be the same as FlowLogRecord defined in enterprise/pkg/lb/flowlogs/map.go */
struct lb_flow_log_entry_v4 {
	/* Key */
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	__u8 nexthdr;
	__u8 pad0;
	__u8 pad1;
	__u8 pad2;
	/* Value */
	__u64 bytes;
};

static __always_inline int lb_flow_log_v4(struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	struct lb_flow_log_entry_v4 *e;
	void *data = ctx_data(ctx);
	struct iphdr *ipv4_hdr;

	ipv4_hdr = data + sizeof(struct ethhdr);
	if (ctx_no_room(ipv4_hdr + 1, data_end))
		return CTX_ACT_DROP;

	e = ringbuf_reserve(&CILIUM_LB_FLOW_LOG_RB_V4_MAP, sizeof(*e), 0);
	if (!e)
		return CTX_ACT_OK;

	e->saddr = ipv4_hdr->saddr;
	e->daddr = ipv4_hdr->daddr;
	e->nexthdr = ipv4_hdr->protocol;

	if (e->nexthdr == IPPROTO_TCP || e->nexthdr == IPPROTO_UDP) {
		if (l4_load_ports(ctx, ETH_HLEN + ipv4_hdrlen(ipv4_hdr), &e->sport) < 0) {
			ringbuf_discard(e, 0);
			return CTX_ACT_DROP;
		}
	}

	e->bytes += data_end - data;

	ringbuf_submit(e, 0);
	return CTX_ACT_OK;
}
#endif

#ifdef ENABLE_IPV6
static __always_inline int lb_flow_log_v6(struct __ctx_buff *ctx)
{
	/* IPv6 is not supported in ilb, yet, plus for IPv6 it would really be
	 * better to wait until the optimized implementation (in-eBPF aggregation)
	 */
	return CTX_ACT_OK;
}
#endif

static __always_inline int lb_flow_log_generic(struct __ctx_buff *ctx __maybe_unused)
{
	/* This could be implemented via 1 global ring-buffer, as this
	 * shouldn't be the biggest source of traffic
	 */
	return CTX_ACT_OK;
}

static __always_inline int
lb_flow_log(struct __ctx_buff *ctx, __u16 proto)
{
	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		return lb_flow_log_v4(ctx);
#endif
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		return lb_flow_log_v6(ctx);
#endif
	default:
		return lb_flow_log_generic(ctx);
	}

	return CTX_ACT_OK;
}
#endif /* LB_FLOW_LOGS_ENABLED */

static __always_inline int
xdp_early_hook(struct __ctx_buff *ctx __maybe_unused, __u16 proto __maybe_unused)
{
	int ret = CTX_ACT_OK;

#ifdef LB_FLOW_LOGS_ENABLED
	ret = lb_flow_log(ctx, proto);
#endif

	return ret;
}

#define xdp_early_hook xdp_early_hook
