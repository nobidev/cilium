/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/enterprise_privnet.h"

#undef host_egress_policy_hook
static __always_inline int
host_egress_policy_hook(struct __ctx_buff *ctx __maybe_unused,
			__u32 src_sec_identity __maybe_unused,
			__s8 *ext_err __maybe_unused)
{
       return CTX_ACT_OK;
}

static __always_inline int
enterprise_privnet_do_netdev(struct __ctx_buff *ctx, __u16 proto, __u32 __maybe_unused identity,
			     enum trace_point obs_point,  const bool __maybe_unused from_host)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};

	void __maybe_unused *data, *data_end;
	struct ipv6hdr __maybe_unused *ip6;
	struct iphdr __maybe_unused *ip4;
	const struct privnet_fib_val *sip_val __maybe_unused = NULL;
	const struct privnet_fib_val *dip_val __maybe_unused = NULL;
	const struct remote_endpoint_info *info __maybe_unused;
	__s8 __maybe_unused ext_err = 0;
	int ret = CTX_ACT_OK;

	if (!CONFIG(privnet_enable))
		return ret;

	/* we do not expect privnet traffic coming from host */
	if (from_host)
		return ret;

	switch (proto) {
	case bpf_htons(ETH_P_ARP):
		send_trace_notify(ctx, obs_point, UNKNOWN_ID, UNKNOWN_ID, TRACE_EP_ID_UNKNOWN,
				  ctx->ingress_ifindex, trace.reason, trace.monitor, proto);
		return handle_privnet_arp(ctx, &cilium_privnet_fib, CONFIG(privnet_network_id));
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
			return send_drop_notify_error(ctx, identity, DROP_INVALID,
						      METRIC_INGRESS);

		if (is_icmp6_ndp(ctx, ip6, ETH_HLEN)) {
			/* Reply to the neighbor solicitation messages if necessary */
			/* (i.e., they target a known IP reachable through this TGW), */
			/* and punt all the others up to the stack unmodified, to */
			/* make sure we don't break local neighbor discovery. */
			return handle_privnet_ns(ctx, &cilium_privnet_fib,
						 CONFIG(privnet_network_id), false);
		}

		ret = privnet_egress_ipv6(ctx, &cilium_privnet_fib, CONFIG(privnet_network_id),
					  &sip_val, &dip_val);
		if (IS_ERR(ret))
			return ret;

		if (!sip_val || !dip_val || is_privnet_route_entry(dip_val)) {
			/* See comment for IPv4 */
			return DROP_UNROUTABLE;
		}

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

#ifdef TUNNEL_MODE
		info = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr, 0);
		if (info && info->flag_has_tunnel_ep && !info->flag_skip_tunnel) {
			if (is_privnet_route_entry(sip_val)) {
				/* see comment for IPv4 */
				return encap_and_redirect_with_nodeid(ctx, info,
					CONFIG(privnet_unknown_sec_id),
					info->sec_identity,
					&trace, proto);
			}

			ret = privnet_policy_egress6(ctx, ip6, info->sec_identity,
						     &ext_err);
			if (ret != CTX_ACT_OK)
				return send_drop_notify_ext(ctx, identity,
							    info->sec_identity, 0,
							    ret, ext_err,
							    METRIC_EGRESS);

			return encap_and_redirect_with_nodeid(ctx, info,
				identity,
				info->sec_identity,
				&trace, proto);
		}
#endif
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
			return send_drop_notify_error(ctx, identity, DROP_INVALID,
							METRIC_INGRESS);

		ret = privnet_egress_ipv4(ctx, &cilium_privnet_fib, CONFIG(privnet_network_id),
					  &sip_val, &dip_val);
		if (IS_ERR(ret))
			return ret;

		if (!sip_val) {
			/* Source IP is not translated and there is no source route match, */
			/* so there is no way to route back to the sender. It is better to */
			/* drop the packet now. */
			return DROP_UNROUTABLE;
		}

		if (!dip_val || is_privnet_route_entry(dip_val)) {
			/* dst_ip is not translated to exact endpoint or dip_val exists but
			 * for a route entry ( there is no ep associated with it).
			 * In both cases, we want to drop the packet to avoid network
			 * segmentation leakage.
			 */
			return DROP_UNROUTABLE;
		}

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

#ifdef TUNNEL_MODE
		info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
		if (info && info->flag_has_tunnel_ep && !info->flag_skip_tunnel) {
			if (is_privnet_route_entry(sip_val)) {
				/* if packet is coming from source which matches a route */
				/* (i.e. there is no ep associated with it), */
				/* we skip egress policy check and redirect to destination node */
				/* using privnet_unknown_flow identity. */
				return encap_and_redirect_with_nodeid(ctx, info,
					CONFIG(privnet_unknown_sec_id), info->sec_identity,
					&trace, proto);
			}

			/* egress policy check is done after nat to pip and concluding that
			 * it is not an unknown flow.
			 */
			ret = privnet_policy_egress4(ctx, ip4, info->sec_identity,
						     &ext_err);
			if (ret != CTX_ACT_OK)
				return send_drop_notify_ext(ctx, identity,
							    info->sec_identity, 0,
							    ret, ext_err,
							    METRIC_EGRESS);

			return encap_and_redirect_with_nodeid(ctx, info,
							      identity, info->sec_identity,
							      &trace, proto);
		}

#endif
		break;
#endif /* ENABLE_IPV4 */
	default:
		break;
	}

	return ret;
}
