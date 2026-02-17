/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/enterprise_privnet.h"
#include "lib/network_device.h"

static __always_inline int enterprise_privnet_from_overlay(struct __ctx_buff *ctx __maybe_unused,
							   __u16 proto,
							   __s8 *ext_err __maybe_unused)
{
	void __maybe_unused *data_end, *data;
	__u32 src_sec_identity __maybe_unused = 0;
	struct iphdr *ip4 __maybe_unused;
	struct ipv6hdr *ip6 __maybe_unused;
	const struct privnet_pip_val *dst_pip_val __maybe_unused = NULL;
	const struct privnet_pip_val *src_pip_val __maybe_unused = NULL;
	const struct privnet_fib_val *dip_fib_val __maybe_unused = NULL;
	struct bpf_tunnel_key tunnel_key __maybe_unused = {};
	bool unknown_flow __maybe_unused = false;
	int privnet_ifindex __maybe_unused;
	int ret __maybe_unused = CTX_ACT_OK;

	if (!CONFIG(privnet_enable)) {
		/* privnet isn't enabled, so we're always in PIP space */
		set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);
		return ret;
	}

	/* From overlay privnet code is only required in INB */
	if (!CONFIG(privnet_bridge_enable)) {
		/* We're not on the bridge. That means in from_overlay, the destination
		 * is always in PIP space, as it points to a local endpoint.
		 * The source, however, is unknown. It might also be in the PIP space
		 * for pod to pod flows, or it might be a netIP for the unknown flow.
		 * Set the source NetID to UNKNOWN.
		 */
		set_privnet_net_ids(PRIVNET_UNKNOWN_NET_ID, PRIVNET_PIP_NET_ID);
		return ret;
	}

	/* On INB, the source must be in PIP space, as it comes from a worker node.
	 * The destination unknown. It might also be in PIP space for pod to extEP flow,
	 * or it might be in a netIP space for the unknown flow.
	 * Set the destination NetID to UNKNOWN.
	 */
	set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_UNKNOWN_NET_ID);

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		if (ctx_get_tunnel_key(ctx, &tunnel_key, TUNNEL_KEY_WITHOUT_SRC_IP, 0) < 0)
			return DROP_NO_TUNNEL_KEY;

		if (tunnel_key.tunnel_id == CONFIG(privnet_unknown_sec_id))
			unknown_flow = true;

		src_sec_identity = get_id_from_tunnel_id(tunnel_key.tunnel_id, proto);

		if (!unknown_flow) {
			/* Not unknown flow, so we're in PIP space */
			set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);
			ret = privnet_ext_ep_policy_ingress6(ctx, ip6, src_sec_identity, ext_err);
			if (IS_ERR(ret))
				return ret;
		}

		ret = privnet_ingress_ipv6(ctx, 0, unknown_flow,
					   &src_pip_val, &dst_pip_val);
		if (IS_ERR(ret))
			return ret;

		if (!src_pip_val || src_pip_val->ifindex == 0) {
			if (!revalidate_data(ctx, &data, &data_end, &ip6))
				return DROP_INVALID;

			/* We could not perform SNAT, hence we cannot handle this packet. */
			if (lookup_ip6_endpoint(ip6)) {
				/* The destination is a local endpoint, hence let processing continue. */
				return CTX_ACT_OK;
			}

			/* Drop all other packets, to prevent incorrectly forwarding them. */
			return DROP_UNROUTABLE;
		}
		privnet_ifindex = (int)src_pip_val->ifindex;

		if (src_pip_val && dst_pip_val) {
			/* fully xlated flow*/

			union macaddr *smac = device_mac(privnet_ifindex);
			union macaddr dmac = dst_pip_val->mac;

			if (!smac)
				return DROP_NO_DEVICE;
			if (eth_store_saddr(ctx, smac->addr, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_daddr(ctx, (__u8 *)&dmac, 0) < 0)
				return DROP_WRITE_ERROR;

			return ctx_redirect(ctx, privnet_ifindex, 0);
		}

		if (unknown_flow && src_pip_val) {
			if (!revalidate_data(ctx, &data, &data_end, &ip6))
				return DROP_INVALID;

			union v6addr daddr = {};
			__u16 sn_id;

			ipv6_addr_copy(&daddr, (union v6addr *)&ip6->daddr);

			/* network and subnet IDs are based on original source ip (pip). */
			sn_id = privnet_subnet_id_lookup6(src_pip_val->net_id, src_pip_val->ip6);
			dip_fib_val = privnet_fib_lookup6(src_pip_val->net_id, sn_id, daddr);

			return privnet_redirect_neigh_fib_ipv6(dip_fib_val, &daddr,
							       privnet_ifindex);
		}

		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		if (ctx_get_tunnel_key(ctx, &tunnel_key, TUNNEL_KEY_WITHOUT_SRC_IP, 0) < 0)
			return DROP_NO_TUNNEL_KEY;

		if (tunnel_key.tunnel_id == CONFIG(privnet_unknown_sec_id))
			unknown_flow = true;

		src_sec_identity = get_id_from_tunnel_id(tunnel_key.tunnel_id, proto);

		/* Evaluate ingress policy before reverse NAT, as policies are based on
		 * PIPs.
		 * For traffic with unknown sec_id, unknown_flow is true, we should skip
		 * ingress policy evaluation as we do not have ep info for the destination.
		 */
		if (!unknown_flow) {
			/* Not unknown flow, so we're in PIP space */
			set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);
			ret = privnet_ext_ep_policy_ingress4(ctx, ip4, src_sec_identity, ext_err);
			if (IS_ERR(ret))
				return ret;
		}

		ret = privnet_ingress_ipv4(ctx, 0, unknown_flow,
					   &src_pip_val, &dst_pip_val);
		if (IS_ERR(ret))
			return ret;

		/* Evaluate privnet_ifindex for sending packet. It is common for all destinations belonging
		 * to the same private network. Currently, privnet_ifindex is saved in revnat_val.
		 * We expect the source to be some endpoint in kubernetes cluster
		 * which is initiating the flow.
		 */
		if (!src_pip_val || src_pip_val->ifindex == 0) {
			if (!revalidate_data(ctx, &data, &data_end, &ip4))
				return DROP_INVALID;

			if (lookup_ip4_endpoint(ip4)) {
				/* The destination is a local endpoint, hence let processing continue. */
				return CTX_ACT_OK;
			}

			/* Drop all other packets from unknown source,
			 * to prevent incorrectly forwarding them.
			 */

			return DROP_UNROUTABLE;
		}
		privnet_ifindex = (int)src_pip_val->ifindex;

		if (src_pip_val && dst_pip_val) {
			/* Fully xlated flow. */

			union macaddr *smac = device_mac(privnet_ifindex);
			union macaddr dmac = dst_pip_val->mac;

			if (!smac)
				return DROP_NO_DEVICE;
			if (eth_store_saddr(ctx, smac->addr, 0) < 0)
				return DROP_WRITE_ERROR;

			if (eth_store_daddr(ctx, (__u8 *)&dmac, 0) < 0)
				return DROP_WRITE_ERROR;

			return ctx_redirect(ctx, privnet_ifindex, 0);
		}

		if (unknown_flow && src_pip_val) {
			if (!revalidate_data(ctx, &data, &data_end, &ip4))
				return DROP_INVALID;

			__u16 sn_id;

			/* network and subnet IDs are based on original source ip (pip). */
			sn_id = privnet_subnet_id_lookup4(src_pip_val->net_id, src_pip_val->ip4);
			dip_fib_val = privnet_fib_lookup4(src_pip_val->net_id, sn_id, ip4->daddr);

			return privnet_redirect_neigh_fib_ipv4(dip_fib_val, ip4->daddr,
							       privnet_ifindex);
		}

		break;
#endif /* ENABLE_IPV4 */
	default:
		break;
	}

	return ret;
}

static __always_inline int enterprise_privnet_to_overlay(struct __ctx_buff *ctx __maybe_unused,
							 __be16 __maybe_unused proto)
{
	if (!CONFIG(privnet_enable)) {
		/* privnet isn't enabled, so we're always in PIP space */
		set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);
		return CTX_ACT_OK;
	}

	if (!CONFIG(privnet_bridge_enable)) {
		/* We're not on the bridge. The source must be in PIP space, as it comes from
		 * a local endpoint. The destination is unknown. It might also be in PIP space
		 * for the pod to pod flow, or it might be in a netIP space for the unknown flow.
		 * Set the destination NetID to UNKNOWN.
		 */
		set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_UNKNOWN_NET_ID);
		return CTX_ACT_OK;
	}
	/* We're on the bridge. That means in to_overlay, the destination
	 * is always in PIP space, as it points to a pod on a worker node.
	 * The source, however, is unknown. It might also be in the PIP space
	 * for extEP to pod flows, or it might be a netIP for the unknown flow.
	 * Set the source NetID to UNKNOWN.
	 */
	set_privnet_net_ids(PRIVNET_UNKNOWN_NET_ID, PRIVNET_PIP_NET_ID);

	return CTX_ACT_OK;
}
