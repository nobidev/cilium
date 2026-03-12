// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "scapy.h"

/* Datapath dummy config for tests */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define TUNNEL_MODE
#define ENCAP_IFINDEX 1
#define privnet_tunnel_id 99

/* Enable debug output */
#define DEBUG

#define CILIUM_DHCP_IFINDEX 123

static int redirect_target_ifindex;

#define ctx_redirect mock_ctx_redirect
static __always_inline int mock_ctx_redirect(const struct __sk_buff __maybe_unused *ctx,
					     int ifindex, __u32 __maybe_unused flags)
{
	redirect_target_ifindex = ifindex;
	return CTX_ACT_REDIRECT;
}

#include "enterprise_privnet_common.h"

#include "lib/bpf_lxc.h"

/* Include test helpers */
#include "tests/lib/enterprise_privnet.h"
#include "tests/lib/ipcache.h"
#include "tests/lib/policy.h"

/* Enable privnet */
ASSIGN_CONFIG(bool, privnet_enable, true)
ASSIGN_CONFIG(bool, privnet_local_access_enable, false)
ASSIGN_CONFIG(bool, privnet_host_reachability, true)
ASSIGN_CONFIG(__u32, privnet_unknown_sec_id, 99) /* tunnel id 99 is reserved for unknown privnet flow */
ASSIGN_CONFIG(__u32, interface_ifindex, IFINDEX)
ASSIGN_CONFIG(__u32, cilium_dhcp_ifindex, CILIUM_DHCP_IFINDEX)
ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_two_addr}) /* set lxc mac */

static const union v4addr lxc_privnet_ipv4 = { .be32 = V4_NET_IP_1 };
static const union v6addr lxc_privnet_ipv6 = { .addr = v6_svc_one_addr };

#define HOST_IP v4_node_one

PKTGEN("tc", "01_tcp_from_host_to_privnet_snat")
int host_snat_ingress_pktgen(struct __ctx_buff *ctx)
{
	BUF_DECL(HOST_TO_POD, privnet_host_to_pod_tcp_syn);
	build_privnet_packet(ctx, HOST_TO_POD);
	return 0;
}

SETUP("tc", "01_tcp_from_host_to_privnet_snat")
int host_snat_ingress_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);

	ipcache_v4_add_entry(HOST_IP, 0, HOST_ID, 0, 0);

	set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	policy_add_egress_allow_all_entry();
	policy_add_ingress_allow_l3_l4_entry(0, 0, 0, 0);

	return pod_receive_packet_by_tailcall(ctx);
}

CHECK("tc", "01_tcp_from_host_to_privnet_snat")
int host_snat_ingress_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, CTX_ACT_OK);

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *ip4;

	data += sizeof(__u32);
	data += sizeof(struct ethhdr);

	if (data + sizeof(struct iphdr) > data_end)
		test_fatal("packet too short for IP header");

	ip4 = data;

	if (ip4->saddr != PRIVNET_LINK_LOCAL_SNAT_IPV4)
		test_fatal("expected src 169.254.7.1 (0x%x), got 0x%x",
			   PRIVNET_LINK_LOCAL_SNAT_IPV4, ip4->saddr);

	if (ip4->daddr != V4_NET_IP_1)
		test_fatal("expected dst netIP (0x%x), got 0x%x",
			   V4_NET_IP_1, ip4->daddr);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

/* The test case depends on the CT / NAT map entries created by
 * the previous test case.
 */
PKTGEN("tc", "02_tcp_from_privnet_to_host_rev_snat")
int host_rev_snat_egress_pktgen(struct __ctx_buff *ctx)
{
	BUF_DECL(POD_TO_HOST, privnet_pod_to_host_tcp_synack);
	build_privnet_packet(ctx, POD_TO_HOST);
	return 0;
}

SETUP("tc", "02_tcp_from_privnet_to_host_rev_snat")
int host_rev_snat_egress_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);

	ipcache_v4_add_entry(HOST_IP, 0, HOST_ID, 0, 0);

	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "02_tcp_from_privnet_to_host_rev_snat")
int host_rev_snat_egress_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_OK);

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *ip4;

	data += sizeof(__u32);
	data += sizeof(struct ethhdr);

	if (data + sizeof(struct iphdr) > data_end)
		test_fatal("packet too short for IP header");

	ip4 = data;

	if (ip4->saddr != V4_POD_IP_1)
		test_fatal("expected src PIP (0x%x), got 0x%x",
			   V4_POD_IP_1, ip4->saddr);

	if (ip4->daddr != HOST_IP)
		test_fatal("expected dst HOST_IP (0x%x), got 0x%x",
			   HOST_IP, ip4->daddr);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}
