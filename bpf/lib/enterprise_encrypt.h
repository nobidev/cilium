/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#ifdef ENABLE_ENCRYPTION_POLICY

#include "lib/wireguard.h"

/* flow_needs_encrypt will check if the current packet needs encryption
 * by checking policy entries for both flow directions.
 */
static __always_inline bool
flow_needs_encrypt(__u32 src_id, __be16 src_port, __u32 dst_id, __be16 dst_port, __u8 proto) {
	struct encryption_policy_entry *entry;
	struct encryption_policy_key key = {
		.lpm_key = { ENCRYPTION_POLICY_FULL_PREFIX, {} },
		.src_sec_identity = src_id,
		.dst_sec_identity = dst_id,
		.protocol = proto,
		.port = dst_port,
	};

	/* check if current direction (src_id, dst_id, dst_port, proto) needs encryption */
	entry = map_lookup_elem(&ENCRYPTION_POLICY_MAP, &key);
	if (entry)
		return entry->encrypt;

	/* check if reply direction (dst_id, src_id, src_port, proto) needs encryption */
	key.src_sec_identity = dst_id;
	key.dst_sec_identity = src_id;
	key.port = src_port;

	entry = map_lookup_elem(&ENCRYPTION_POLICY_MAP, &key);
	if (entry)
		return entry->encrypt;

	return false;
}

#undef host_wg_encrypt_hook
static __always_inline int
host_wg_encrypt_hook(struct __ctx_buff *ctx, __be16 proto)
{
	struct remote_endpoint_info *dst = NULL;
	struct remote_endpoint_info __maybe_unused *src = NULL;
	void *data, *data_end;
	struct ipv6hdr __maybe_unused *ip6, *inner_ip6;
	struct iphdr __maybe_unused *ip4, *inner_ip4;
	bool from_tunnel __maybe_unused = false;
	__u32 magic __maybe_unused = 0;

	__u8 __maybe_unused l4_proto;
	__u32 __maybe_unused l4_off = 0, ipv6_off;
	struct ipv4_frag_l4ports __maybe_unused ports;
	int __maybe_unused ret = 0;
	__u16 __maybe_unused inner_l3_proto;
	__u32 __maybe_unused inner_l3_off;

	if (!eth_is_supported_ethertype(proto))
		return DROP_UNSUPPORTED_L2;

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
#ifdef ENABLE_NODE_ENCRYPTION
		/* Previously, ICMPv6 NA (reply to NS) was sent over cilium_wg0,
		 * which resulted in neigh entry not being created due to
		 * IFF_POINTOPOINT | IFF_NOARP set on cilium_wg0. Therefore,
		 * NA should not be sent over WG.
		 */
		if (ip6->nexthdr == IPPROTO_ICMPV6) {
			__u8 icmp_type;

			if (data + sizeof(*ip6) + ETH_HLEN +
			    sizeof(struct icmp6hdr) > data_end)
				return DROP_INVALID;

			if (icmp6_load_type(ctx, ETH_HLEN + sizeof(struct ipv6hdr),
					    &icmp_type) < 0)
				return DROP_INVALID;

			if (icmp_type == ICMP6_NA_MSG_TYPE)
				goto out;
		}
#endif
		dst = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr, 0);
		src = lookup_ip6_remote_endpoint((union v6addr *)&ip6->saddr, 0);

		/* ENABLE_ENCRYPTION_POLICY changes */
		l4_proto = ip6->nexthdr;
		ipv6_off = ipv6_hdrlen(ctx, &l4_proto);
		if (ipv6_off < 0)
			return ipv6_off;

		l4_off = ETH_HLEN + ipv6_off;
		/* ENABLE_ENCRYPTION_POLICY changes */
		break;
#endif
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		/* ENABLE_ENCRYPTION_POLICY changes */
		l4_proto = ip4->protocol;
		l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
		/* ENABLE_ENCRYPTION_POLICY changes */

# if defined(HAVE_ENCAP)
		/* In tunneling mode WG needs to encrypt tunnel traffic,
		 * so that src sec ID can be transferred.
		 *
		 * This also handles IPv6, as IPv6 pkts are encapsulated w/
		 * IPv4 tunneling.
		 */
		if (ctx_is_overlay(ctx)) {
			/* ENABLE_ENCRYPTION_POLICY changes */
			inner_l3_proto = vxlan_get_inner_proto(data, data_end, l4_off);
			switch (inner_l3_proto) {
#ifdef ENABLE_IPV6
			case bpf_htons(ETH_P_IPV6):
				ret = vxlan_get_inner_ipv6(data, data_end, l4_off, &inner_ip6);
				if (!ret)
					return DROP_INVALID;
				if (!inner_ip6)
					return DROP_INVALID;

				dst = lookup_ip6_remote_endpoint((union v6addr *)&inner_ip6->daddr, 0);
				src = lookup_ip6_remote_endpoint((union v6addr *)&inner_ip6->saddr, 0);

				l4_proto = inner_ip6->nexthdr;
				/* calculate offset of inner ip packet */
				inner_l3_off = l4_off + sizeof(struct udphdr) + sizeof(struct vxlanhdr) +
					       sizeof(struct ethhdr);

				/* with the offset of the inner ip packet, calculate length of inner ipv6 header */
				ipv6_off = ipv6_hdrlen_offset(ctx, &l4_proto, inner_l3_off);
				if (ipv6_off < 0)
					return ipv6_off;

				l4_off = inner_l3_off + ipv6_off;
				break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
			case bpf_htons(ETH_P_IP):
				ret = vxlan_get_inner_ipv4(data, data_end, l4_off, &inner_ip4);
				if (!ret)
					return DROP_INVALID;
				if (!inner_ip4)
					return DROP_INVALID;

				dst = lookup_ip4_remote_endpoint(inner_ip4->daddr, 0);
				src = lookup_ip4_remote_endpoint(inner_ip4->saddr, 0);

				l4_proto = inner_ip4->protocol;

				l4_off = l4_off + sizeof(struct udphdr) + sizeof(struct vxlanhdr) +
					 sizeof(struct ethhdr) + ipv4_hdrlen(inner_ip4);
				break;
#endif /* ENABLE_IPV4 */
			default:
				goto out;
			}
			goto maybe_encrypt;
		}
		/* ENABLE_ENCRYPTION_POLICY changes */
# endif /* HAVE_ENCAP */

		dst = lookup_ip4_remote_endpoint(ip4->daddr, 0);
		src = lookup_ip4_remote_endpoint(ip4->saddr, 0);
		break;
#endif
	default:
		goto out;
	}

#ifndef ENABLE_NODE_ENCRYPTION
	/* A pkt coming from L7 proxy (i.e., Envoy or the DNS proxy on behalf of
	 * a client pod) has src IP addr of a host, but not of the client pod
	 * (if
	 * --dnsproxy-enable-transparent-mode=false). Such a pkt must be
	 *  encrypted.
	 */
	magic = ctx->mark & MARK_MAGIC_HOST_MASK;
	if (magic == MARK_MAGIC_PROXY_INGRESS || magic == MARK_MAGIC_PROXY_EGRESS)
		goto maybe_encrypt;
#if defined(TUNNEL_MODE)
	/* In tunneling mode the mark might have been reset. Check TC index instead.
	 */
	if (tc_index_from_ingress_proxy(ctx) || tc_index_from_egress_proxy(ctx))
		goto maybe_encrypt;
#endif /* TUNNEL_MODE */

	/* Unless node encryption is enabled, we don't want to encrypt
	 * traffic from the hostns (an exception - L7 proxy traffic).
	 *
	 * NB: if iptables has SNAT-ed the packet, its sec id is HOST_ID.
	 * This means that the packet won't be encrypted. This is fine,
	 * as with --encrypt-node=false we encrypt only pod-to-pod packets.
	 */
	if (!src || src->sec_identity == HOST_ID)
		goto out;
#endif /* !ENABLE_NODE_ENCRYPTION */

	/* We don't want to encrypt any traffic that originates from outside
	 * the cluster. This check excludes DSR traffic from the LB node to a remote backend.
	 */
	if (!src || !identity_is_cluster(src->sec_identity))
		goto out;

	/* If source is remote node we should treat it like outside traffic.
	 * This is possible when connection is done from pod to load balancer with DSR enabled.
	 */
	if (identity_is_remote_node(src->sec_identity))
		goto out;

maybe_encrypt: __maybe_unused
	/* Redirect to the WireGuard tunnel device if the encryption is
	 * required.
	 */
	/* ENABLE_ENCRYPTION_POLICY changes */
	/* For now encryption policies are only supported with UDP and TCP traffic */
	switch (l4_proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		/* load sport + dport into tuple */
		if (l4_load_ports(ctx, l4_off, &ports.sport) < 0)
			return DROP_INVALID;

		if (src && dst) {
			if (!flow_needs_encrypt(src->sec_identity,
						ports.sport,
						dst->sec_identity,
						ports.dport,
						l4_proto))
				goto out;
		}
		break;
	default:
		goto out;
	}
	/* ENABLE_ENCRYPTION_POLICY changes */
	if (dst && dst->key) {
		if (src)
			set_identity_mark(ctx, src->sec_identity, MARK_MAGIC_IDENTITY);
overlay_encrypt: __maybe_unused
		return ctx_redirect(ctx, WG_IFINDEX, 0);
	}

out:
	return CTX_ACT_OK;
}

#endif /* ENABLE_ENCRYPTION_POLICY */
