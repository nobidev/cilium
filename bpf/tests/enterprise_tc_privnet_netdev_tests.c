// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "scapy.h"

/* Datapath dummy config for tests */
#define ENABLE_IPV4
#define ENABLE_IPV6
#define TUNNEL_MODE
#define ENCAP_IFINDEX 1
#define privnet_tunnel_id 99

/* Enable debug output */
#define DEBUG

#include "enterprise_privnet_common.h"
#include <bpf/config/node.h>
#include <lib/enterprise_ext_eps_maps.h>

static __always_inline int
mock_ext_eps_policy_can_access(struct __ctx_buff __maybe_unused *ctx,
			       struct endpoint_key __maybe_unused *key,
			       __u32 __maybe_unused sec_identity, __u16 __maybe_unused ethertype,
			       __be16 __maybe_unused dport, __u8 __maybe_unused proto,
			       int __maybe_unused l4_off, __u8 __maybe_unused *match_type,
			       int __maybe_unused dir, bool __maybe_unused is_untracked_fragment,
			       __u8 __maybe_unused *audited, __s8 __maybe_unused *ext_err,
			       __u16 __maybe_unused *proxy_port, __u32 __maybe_unused *cookie)
{
	return CTX_ACT_OK;
}

#undef ext_ep_policy_verdict
#define ext_ep_policy_verdict mock_ext_eps_policy_can_access

#undef EFFECTIVE_EP_ID
#undef EVENT_SOURCE

/* Include an actual datapath code */
#include "lib/bpf_host.h"

#include "tests/lib/enterprise_privnet.h"
#include "tests/lib/ipcache.h"

/* Enable privnet */
ASSIGN_CONFIG(bool, privnet_enable, true)
ASSIGN_CONFIG(__u16, privnet_network_id, NET_ID)
ASSIGN_CONFIG(__u32, privnet_unknown_sec_id, 99) /* tunnel id 99 is reserved for unknown privnet flow */
ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_two_addr}) /* set device mac */

PKTGEN("tc", "01_icmp_from_netdev_nat_src_dst")
int privnet_icmp_from_netdev_nat_src_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, NETIP_ICMP_REQ);
	return 0;
}

SETUP("tc", "01_icmp_from_netdev_nat_src_dst")
int privnet_icmp_from_netdev_nat_src_dst_setup(struct __ctx_buff *ctx)
{
	privnet_v4_add_endpoint_entry(NET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, V4_NET_IP_2, V4_POD_IP_2);

	ipcache_v4_add_entry(V4_POD_IP_1, 0, 1001, INB_IP, 0);
	ipcache_v4_add_entry(V4_POD_IP_2, 0, 1002, NODE_IP, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "01_icmp_from_netdev_nat_src_dst")
int privnet_icmp_from_netdev_nat_src_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	/* packets are redirected to tunnel device */
	assert_status_code(ctx, TC_ACT_REDIRECT);

	ASSERT_CTX_BUF_OFF("privnet_icmp_from_netdev_nat_src_dst", "IP", ctx,
			   sizeof(__u32), PODIP_ICMP_REQ,
			   sizeof(BUF(PODIP_ICMP_REQ)));

	privnet_v4_del_endpoint_entry(NET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, V4_NET_IP_2, V4_POD_IP_2);

	test_finish();
}

PKTGEN("tc", "02_icmp_from_netdev_respond_arp")
int privnet_icmp_from_netdev_respond_arp_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, NETIP_ARP_REQ);
	return 0;
}

SETUP("tc", "02_icmp_from_netdev_respond_arp")
int privnet_icmp_from_netdev_respond_arp_setup(struct __ctx_buff *ctx)
{
	privnet_v4_add_endpoint_entry(NET_ID, V4_NET_IP_2, V4_POD_IP_2);
	return netdev_receive_packet(ctx);
}

CHECK("tc", "02_icmp_from_netdev_respond_arp")
int privnet_icmp_from_netdev_respond_arp_check(struct __ctx_buff *ctx)
{
	test_init();

	/* The ARP response should be redirected back */
	assert_status_code(ctx, TC_ACT_REDIRECT);

	ASSERT_CTX_BUF_OFF("privnet_icmp_from_netdev_respond_arp", "Ether", ctx,
			   sizeof(__u32), NETIP_ARP_RES,
			   sizeof(BUF(NETIP_ARP_RES)));

	privnet_v4_del_endpoint_entry(NET_ID, V4_NET_IP_2, V4_POD_IP_2);

	test_finish();
}

PKTGEN("tc", "03_icmp6_from_netdev_respond_ns")
int privnet_icmp6_from_netdev_respond_ns_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, NETDEV_ICMP6_NS);
	return 0;
}

SETUP("tc", "03_icmp6_from_netdev_respond_ns")
int privnet_icmp6_from_netdev_respond_ns_setup(struct __ctx_buff *ctx)
{
	privnet_v6_add_endpoint_entry(NET_ID,
				      (const union v6addr *)V6_NET_IP_1,
				      (const union v6addr *)V6_POD_IP_1);
	return netdev_receive_packet(ctx);
}

CHECK("tc", "03_icmp6_from_netdev_respond_ns")
int privnet_icmp6_from_netdev_respond_ns_check(struct __ctx_buff *ctx)
{
	test_init();

	/* packets are redirected back to device */
	assert_status_code(ctx, TC_ACT_REDIRECT);

	ASSERT_CTX_BUF_OFF("privnet_icmp6_from_netdev_respond_ns", "Ether", ctx,
			   sizeof(__u32), NETDEV_ICMP6_NA,
			   sizeof(BUF(NETDEV_ICMP6_NA)));

	privnet_v6_del_endpoint_entry(NET_ID,
				      (const union v6addr *)V6_NET_IP_1,
				      (const union v6addr *)V6_POD_IP_1);

	test_finish();
}

PKTGEN("tc", "04_icmp_from_netdev_miss_src")
int privnet_icmp_from_netdev_miss_src_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, NETIP_ICMP_REQ);
	return 0;
}

SETUP("tc", "04_icmp_from_netdev_miss_src")
int privnet_icmp_from_netdev_miss_src_setup(struct __ctx_buff *ctx)
{
	privnet_v4_add_endpoint_entry(NET_ID, V4_NET_IP_2, V4_POD_IP_2);
	ipcache_v4_add_entry(V4_POD_IP_2, 0, 1002, NODE_IP, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "04_icmp_from_netdev_miss_src")
int privnet_icmp_from_netdev_miss_src_check(struct __ctx_buff *ctx)
{
	test_init();

	/* packet should be dropped */
	assert_status_code(ctx, DROP_UNROUTABLE);

	privnet_v4_del_endpoint_entry(NET_ID, V4_NET_IP_2, V4_POD_IP_2);
	test_finish();
}

PKTGEN("tc", "05_icmp_from_netdev_miss_dst")
int privnet_icmp_from_netdev_miss_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, NETIP_ICMP_REQ);
	return 0;
}

SETUP("tc", "05_icmp_from_netdev_miss_dst")
int privnet_icmp_from_netdev_miss_dst_setup(struct __ctx_buff *ctx)
{
	privnet_v4_add_endpoint_entry(NET_ID, V4_NET_IP_1, V4_POD_IP_1);
	ipcache_v4_add_entry(V4_POD_IP_1, 0, 1001, INB_IP, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "05_icmp_from_netdev_miss_dst")
int privnet_icmp_from_netdev_miss_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	/* packet should be dropped */
	assert_status_code(ctx, DROP_UNROUTABLE);

	privnet_v4_del_endpoint_entry(NET_ID, V4_NET_IP_1, V4_POD_IP_1);
	test_finish();
}
