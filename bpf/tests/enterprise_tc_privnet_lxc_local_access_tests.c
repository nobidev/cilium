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

#define LXC_IFINDEX IFINDEX
#define NETDEV_IFINDEX 142

static int redirect_target_ifindex;

#define redirect_neigh mock_redirect_neigh
static __always_inline __maybe_unused int
mock_redirect_neigh(int ifindex, struct bpf_redir_neigh __maybe_unused *params,
		    int __maybe_unused plen, __u32 __maybe_unused flags)
{
	redirect_target_ifindex = ifindex;
	return CTX_ACT_REDIRECT;
}

#include "enterprise_privnet_common.h"

#include "lib/bpf_lxc.h"

#include "tests/lib/enterprise_privnet.h"
#include "tests/lib/policy.h"

/* Enable privnet */
ASSIGN_CONFIG(bool, privnet_enable, true)
ASSIGN_CONFIG(bool, privnet_local_access_enable, true)
ASSIGN_CONFIG(__u32, privnet_unknown_sec_id, 99) /* tunnel id 99 is reserved for unknown privnet flow */
ASSIGN_CONFIG(__u32, interface_ifindex, LXC_IFINDEX)
ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_two_addr}) /* set lxc mac */

static const union v4addr lxc_privnet_ipv4 = { .be32 = V4_NET_IP_1 };
static const union v6addr lxc_privnet_ipv6 = { .addr = v6_svc_one_addr };

PKTGEN("tc", "01_local_access_egress_from_lxc")
int privnet_local_access_egress_from_lxc_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, NETIP_ICMP_REQ);
	return 0;
}

SETUP("tc", "01_local_access_egress_from_lxc")
int privnet_local_access_egress_from_lxc_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(LXC_IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_add_device_entry(NETDEV_IFINDEX, NET_ID, NULL, NULL);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_subnet_route(NET_ID, SUBNET_ID, V4_NET_IP_2, GATEWAY_IP, NETDEV_IFINDEX);

	return pod_send_packet(ctx);
}

CHECK("tc", "01_local_access_egress_from_lxc")
int privnet_local_access_egress_from_lxc_check(struct __ctx_buff *ctx)
{
	test_init();

	/* packets are redirected to netdev device */
	assert_status_code(ctx, TC_ACT_REDIRECT);

	if (redirect_target_ifindex != NETDEV_IFINDEX)
		test_fatal("unexpected redirect ifindex (got %d, want %d)",
			   redirect_target_ifindex, NETDEV_IFINDEX);

	/* check inner packet headers, src & dst should remain untranslated */
	ASSERT_CTX_BUF_OFF("privnet_local_access_icmp_from_container_no_nat", "IP", ctx,
			   sizeof(__u32), NETIP_ICMP_REQ,
			   sizeof(BUF(NETIP_ICMP_REQ)));

	assert_privnet_net_ids(NET_ID, NET_ID);

	privnet_v4_del_route(NET_ID, SUBNET_ID, V4_NET_IP_2);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(NETDEV_IFINDEX);
	privnet_del_device_entry(LXC_IFINDEX);

	redirect_target_ifindex = 0;

	test_finish();
}
