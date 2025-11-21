/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/enterprise_privnet.h"

static __always_inline int enterprise_privnet_from_lxc(struct __ctx_buff *ctx __maybe_unused,
						       __u16 proto __maybe_unused)
{
	void __maybe_unused *data, *data_end;
	struct ipv6hdr *ip6 __maybe_unused;
	struct iphdr *ip4 __maybe_unused;
	const struct privnet_fib_val *dip_val __maybe_unused;
	int ret __maybe_unused = CTX_ACT_OK;

	if (!CONFIG(privnet_enable))
		return ret;

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		if (is_icmp6_ndp(ctx, ip6, ETH_HLEN))
			return handle_privnet_ns(ctx, &cilium_privnet_fib,
						 CONFIG(privnet_network_id), true);

		ret = privnet_egress_ipv6(ctx, &cilium_privnet_fib, CONFIG(privnet_network_id),
					  NULL, &dip_val);
		if (IS_ERR(ret))
			return ret;
#ifdef TUNNEL_MODE
		if (dip_val && is_privnet_route_entry(dip_val)) {
			struct trace_ctx trace = {
				.reason = TRACE_REASON_UNKNOWN,
				.monitor = TRACE_PAYLOAD_LEN,
			};

			/* see comment for ipv4 */
			struct remote_endpoint_info fake_info = {0};

			/* only support v4 underlay for unknown flows. */
			fake_info.tunnel_endpoint.ip4 = dip_val->ip4;
			fake_info.sec_identity = CONFIG(privnet_unknown_sec_id);

			return encap_and_redirect_with_nodeid(ctx, &fake_info,
							      CONFIG(privnet_unknown_sec_id),
							      fake_info.sec_identity,
							      &trace, proto);
		}
#endif /* TUNNEL_MODE */
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		ret = privnet_egress_ipv4(ctx, &cilium_privnet_fib, CONFIG(privnet_network_id),
					  NULL, &dip_val);
		if (IS_ERR(ret))
			return ret;

#ifdef TUNNEL_MODE
		if (dip_val && is_privnet_route_entry(dip_val)) {
			struct trace_ctx trace = {
				.reason = TRACE_REASON_UNKNOWN,
				.monitor = TRACE_PAYLOAD_LEN,
			};

			/* dip_val is route entry, we can assume that the */
			/* packet is going to INB. Encap the packet with IP */
			/* stored in privnet nat map, it will be node IP of INB and */
			/* with privnet_unknown_sec_id as VNI. */

			struct remote_endpoint_info fake_info = {0};

			fake_info.tunnel_endpoint.ip4 = dip_val->ip4;
			fake_info.sec_identity = CONFIG(privnet_unknown_sec_id);

			return encap_and_redirect_with_nodeid(ctx, &fake_info,
							      CONFIG(privnet_unknown_sec_id),
							      fake_info.sec_identity,
							      &trace, proto);
		}
#endif /* TUNNEL_MODE */
		break;
#endif /* ENABLE_IPV4 */
	default:
		break;
	}

	return ret;
}

#ifdef ENABLE_IPV4
static __always_inline int enterprise_privnet_to_lxc_ipv4_policy(struct __ctx_buff *ctx)
{
	if (CONFIG(privnet_enable)) {
		int ret = privnet_ingress_ipv4(ctx, &cilium_privnet_pip,
					       CONFIG(privnet_network_id), false,
					       NULL, NULL);
		if (IS_ERR(ret))
			return ret;
	}
	return CTX_ACT_OK;
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
static __always_inline int enterprise_privnet_to_lxc_ipv6_policy(struct __ctx_buff *ctx)
{
	if (CONFIG(privnet_enable)) {
		int ret = privnet_ingress_ipv6(ctx, &cilium_privnet_pip,
					       CONFIG(privnet_network_id), false, NULL, NULL);
		if (IS_ERR(ret))
			return ret;
	}
	return CTX_ACT_OK;
}
#endif /* ENABLE_IPV6 */

static __always_inline bool privnet_skip_policy_enforcement(struct __ctx_buff *ctx __maybe_unused)
{
#ifdef HAVE_ENCAP
	if (ctx_load_meta(ctx, CB_FROM_TUNNEL)) {
		struct bpf_tunnel_key tunnel_key = {};

		if (ctx_get_tunnel_key(ctx, &tunnel_key, TUNNEL_KEY_WITHOUT_SRC_IP, 0) < 0)
			return false;

		if (tunnel_key.tunnel_id == CONFIG(privnet_unknown_sec_id))
			return true;
	}
#endif
	return false;
}

__declare_tail(CILIUM_CALL_IPV4_PRIVNET_UNKNOWN_INGRESS)
static __always_inline int tail_handle_ipv4_privnet_unknown_ingress(struct __ctx_buff *ctx)
{
	bool do_redirect = ctx_load_meta(ctx, CB_DELIVERY_REDIRECT);
	bool from_host = ctx_load_meta(ctx, CB_FROM_HOST);
	bool from_tunnel = false;
	int ret = CTX_ACT_OK;

	if (!CONFIG(privnet_enable))
		return ret;

#ifdef HAVE_ENCAP
	from_tunnel = ctx_load_meta(ctx, CB_FROM_TUNNEL);
#endif

	ret = privnet_ingress_ipv4(ctx, &cilium_privnet_pip,
				   CONFIG(privnet_network_id),
				   true, NULL, NULL);
	if (IS_ERR(ret))
		return ret;

	if (do_redirect)
		ret = redirect_ep(ctx, CONFIG(interface_ifindex), from_host, from_tunnel);

	return ret;
}

__declare_tail(CILIUM_CALL_IPV6_PRIVNET_UNKNOWN_INGRESS)
static __always_inline int tail_handle_ipv6_privnet_unknown_ingress(struct __ctx_buff *ctx)
{
	bool do_redirect = ctx_load_meta(ctx, CB_DELIVERY_REDIRECT);
	bool from_host = ctx_load_meta(ctx, CB_FROM_HOST);
	bool from_tunnel = false;
	int ret = CTX_ACT_OK;

	if (!CONFIG(privnet_enable))
		return ret;

#ifdef HAVE_ENCAP
	from_tunnel = ctx_load_meta(ctx, CB_FROM_TUNNEL);
#endif

	ret = privnet_ingress_ipv6(ctx, &cilium_privnet_pip,
				   CONFIG(privnet_network_id),
				   true, NULL, NULL);
	if (IS_ERR(ret))
		return ret;

	if (do_redirect)
		ret = redirect_ep(ctx, CONFIG(interface_ifindex), from_host, from_tunnel);

	return ret;
}

static __always_inline int enterprise_privnet_lxc_policy(struct __ctx_buff *ctx __maybe_unused,
							 __u16 proto __maybe_unused,
							 __u32 src_label __maybe_unused,
							 __s8 *ext_err __maybe_unused)
{
	int ret = CTX_ACT_OK;

	if (!CONFIG(privnet_enable))
		return ret;

	if (!privnet_skip_policy_enforcement(ctx))
		return ret;

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_PRIVNET_UNKNOWN_INGRESS, ext_err);
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_PRIVNET_UNKNOWN_INGRESS, ext_err);
		break;
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

	return ret;
}
