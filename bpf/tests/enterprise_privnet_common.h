/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include "common.h"
#include "pktgen.h"
#include "scapy.h"
#include "tests/mock_skb_metadata.h"

#define NET_ID 100
#define V4_NET_IP_1 v4_svc_one
#define V4_NET_IP_2 v4_svc_two
#define V4_POD_IP_1 v4_pod_one
#define V4_POD_IP_2 v4_pod_two
#define V6_NET_IP_1 v6_svc_one
#define V6_POD_IP_1 v6_pod_one
#define INB_IP v4_ext_one
#define NODE_IP v4_node_one

/* Scapy packet definitions */
BUF_DECL(NETIP_ARP_REQ, privnet_net_ip_arp_req);
BUF_DECL(NETIP_ARP_RES, privnet_net_ip_arp_res);
BUF_DECL(NETIP_ICMP_REQ, privnet_net_ip_icmp_req);
BUF_DECL(NETIP_TCP_SYN, privnet_net_ip_tcp_syn);
BUF_DECL(PODIP_ICMP_REQ, privnet_pod_ip_icmp_req);
BUF_DECL(PODIP_TCP_SYN, privnet_pod_ip_tcp_syn);
BUF_DECL(UNKNOWN_ICMP_REQ, privnet_unknown_flow_icmp_req);
BUF_DECL(LXC_ICMP6_NS, privnet_lxc_ns);
BUF_DECL(LXC_ICMP6_NA, privnet_lxc_na);
BUF_DECL(NETDEV_ICMP6_NS, privnet_netdev_ns);
BUF_DECL(NETDEV_ICMP6_NA, privnet_netdev_na);

#define build_privnet_packet(ctx, buf_name)		\
	do {						\
		struct pktgen builder;			\
		pktgen__init(&builder, ctx);		\
		BUILDER_PUSH_BUF(builder, buf_name);	\
		pktgen__finish(&builder);		\
	} while (0)

#define skb_get_tunnel_key mock_tunnel_key
int mock_tunnel_key(struct __ctx_buff *ctx __maybe_unused,
		    struct bpf_tunnel_key *to,
		    __u32 size __maybe_unused,
		    __u32 flags __maybe_unused)
{
	to->tunnel_id = privnet_tunnel_id;
	return 0;
}
