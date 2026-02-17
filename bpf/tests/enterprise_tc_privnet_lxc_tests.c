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
#include "tests/lib/policy.h"

/* Enable privnet */
ASSIGN_CONFIG(bool, privnet_enable, true)
ASSIGN_CONFIG(bool, privnet_local_access_enable, false)
ASSIGN_CONFIG(__u32, privnet_unknown_sec_id, 99) /* tunnel id 99 is reserved for unknown privnet flow */
ASSIGN_CONFIG(__u32, interface_ifindex, IFINDEX)
ASSIGN_CONFIG(__u32, cilium_dhcp_ifindex, CILIUM_DHCP_IFINDEX)
ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_two_addr}) /* set lxc mac */

static const union v4addr lxc_privnet_ipv4 = { .be32 = V4_NET_IP_1 };
static const union v4addr lxc_privnet_ipv4_other = { .be32 = V4_NET_IP_2 };
static const union v6addr lxc_privnet_ipv6 = { .addr = v6_svc_one_addr };

PKTGEN("tc", "01_icmp_from_container_nat_src_dst")
int privnet_icmp_from_container_nat_src_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, NETIP_ICMP_REQ);
	return 0;
}

SETUP("tc", "01_icmp_from_container_nat_src_dst")
int privnet_icmp_from_container_nat_src_dst_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	/* allow traffic from endpoints */
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "01_icmp_from_container_nat_src_dst")
int privnet_icmp_from_container_nat_src_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_icmp_from_container_nat_src_dst", "IP", ctx,
			   sizeof(__u32), PODIP_ICMP_REQ,
			   sizeof(BUF(PODIP_ICMP_REQ)));

	assert_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

/* TCP syn packet, this test is required to validate checksum is calculated
 * correctly post NAT.
 */

PKTGEN("tc", "02_tcp_from_container_nat_src_dst")
int privnet_tcp_from_container_nat_src_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, NETIP_TCP_SYN);
	return 0;
}

SETUP("tc", "02_tcp_from_container_nat_src_dst")
int privnet_tcp_from_container_nat_src_dst_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	/* allow traffic from endpoints */
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "02_tcp_from_container_nat_src_dst")
int privnet_tcp_from_container_nat_src_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_tcp_from_container_nat_src_dst", "IP", ctx,
			   sizeof(__u32), PODIP_TCP_SYN,
			   sizeof(BUF(PODIP_TCP_SYN)));

	assert_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

/* ICMP packet routed via unknown subnet route */

PKTGEN("tc", "03_icmp_from_container_nat_src_route_dst")
int privnet_icmp_from_container_nat_src_route_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, NETIP_ICMP_REQ);
	return 0;
}

SETUP("tc", "03_icmp_from_container_nat_src_route_dst")
int privnet_icmp_from_container_nat_src_route_dst_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1); /* source entry */
	privnet_v4_add_subnet_route(NET_ID, SUBNET_ID, V4_NET_IP_2, INB_IP, 0); /* destination entry */

	/* allow traffic from endpoints */
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "03_icmp_from_container_nat_src_route_dst")
int privnet_icmp_from_container_nat_src_route_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	/* redirected via unknown flow */
	assert_status_code(ctx, TC_ACT_REDIRECT);

	/* check inner packet headers, dst should remain untranslated */
	ASSERT_CTX_BUF_OFF("privnet_icmp_from_container_nat_src_route_dst", "IP", ctx,
			   sizeof(__u32), UNKNOWN_ICMP_REQ,
			   sizeof(BUF(UNKNOWN_ICMP_REQ)));

	assert_privnet_net_ids(PRIVNET_PIP_NET_ID, NET_ID);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_route(NET_ID, SUBNET_ID, V4_NET_IP_2);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);
	test_finish();
}

/* ICMP packet dropped due to egress segmentation rule */

PKTGEN("tc", "04_icmp_from_container_nat_src_miss_dst")
int privnet_icmp_from_container_nat_src_miss_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, NETIP_ICMP_REQ);
	return 0;
}

SETUP("tc", "04_icmp_from_container_nat_src_miss_dst")
int privnet_icmp_from_container_nat_src_miss_dst_setup(struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_UNROUTABLE,
		.dir = METRIC_EGRESS,
	};
	map_delete_elem(&cilium_metrics, &key);

	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1); /* only source entry */

	/* allow traffic from endpoints */
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "04_icmp_from_container_nat_src_miss_dst")
int privnet_icmp_from_container_nat_src_miss_dst_check(struct __ctx_buff *ctx)
{
	struct metrics_value *entry = NULL;
	struct metrics_key key = {};

	test_init();

	assert_status_code(ctx, CTX_ACT_DROP); /* drop check*/

	/* check reason for drop */
	key.reason = (__u8)-DROP_UNROUTABLE;
	key.dir = METRIC_EGRESS;
	entry = map_lookup_elem(&cilium_metrics, &key);
	if (!entry)
		test_fatal("metrics entry not found");

	assert_privnet_net_ids(PRIVNET_PIP_NET_ID, NET_ID);

	__u64 count = 1;

	assert_metrics_count(key, count);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);
	test_finish();
}

/* Ingress packets going to container */

PKTGEN("tc", "05_icmp_to_container_nat_src_dst")
int privnet_icmp_to_container_nat_src_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, PODIP_ICMP_REQ);
	return 0;
}

SETUP("tc", "05_icmp_to_container_nat_src_dst")
int privnet_icmp_to_container_nat_src_route_dst_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	policy_add_ingress_allow_l3_l4_entry(0, 0, 0, 0);
	return pod_receive_packet_by_tailcall(ctx);
}

CHECK("tc", "05_icmp_to_container_nat_src_dst")
int privnet_icmp_to_container_nat_src_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, CTX_ACT_OK);

	BUF_DECL(EXPECTED_NETIP_ICMP_REQ, privnet_net_ip_icmp_req);
	ASSERT_CTX_BUF_OFF("privnet_icmp_to_container_nat_src_dst", "IP", ctx,
			   sizeof(__u32), EXPECTED_NETIP_ICMP_REQ,
			   sizeof(BUF(EXPECTED_NETIP_ICMP_REQ)));

	assert_privnet_net_ids(NET_ID, NET_ID);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

/* TCP packet going to container */
PKTGEN("tc", "06_tcp_to_container_nat_src_dst")
int privnet_tcp_to_container_nat_src_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, PODIP_TCP_SYN);
	return 0;
}

SETUP("tc", "06_tcp_to_container_nat_src_dst")
int privnet_tcp_to_container_nat_src_route_dst_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	policy_add_ingress_allow_l3_l4_entry(0, 0, 0, 0);
	return pod_receive_packet_by_tailcall(ctx);
}

CHECK("tc", "06_tcp_to_container_nat_src_dst")
int privnet_tcp_to_container_nat_src_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, CTX_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_tcp_to_container_nat_src_dst", "IP", ctx,
			   sizeof(__u32), NETIP_TCP_SYN,
			   sizeof(BUF(NETIP_TCP_SYN)));

	assert_privnet_net_ids(NET_ID, NET_ID);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}

/* Ingress packet coming from unknown source */
PKTGEN("tc", "07_icmp_to_container_unknown_src_nat_dst")
int privnet_icmp_to_container_unknown_src_nat_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, PODIP_ICMP_REQ);
	return 0;
}

SETUP("tc", "07_icmp_to_container_unknown_src_nat_dst")
int privnet_icmp_to_container_unknown_src_nat_dst_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	/* dst is known, no entry for src */
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	set_privnet_net_ids(PRIVNET_UNKNOWN_NET_ID, PRIVNET_PIP_NET_ID);

	ctx_store_meta(ctx, CB_FROM_TUNNEL, 1);
	return pod_receive_packet_by_tailcall(ctx);
}

CHECK("tc", "07_icmp_to_container_unknown_src_nat_dst")
int privnet_icmp_to_container_unknown_src_nat_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, CTX_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_icmp_to_container_unknown_src_nat_dst", "IP", ctx,
			   sizeof(__u32), UNKNOWN_ICMP_REQ,
			   sizeof(BUF(UNKNOWN_ICMP_REQ)));

	assert_privnet_net_ids(NET_ID, NET_ID);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);
	test_finish();
}

/* Ingress packet coming from unknown source and destination is missing
 * in privnet maps.
 */
PKTGEN("tc", "08_icmp_to_container_unknown_src_miss_dst")
int privnet_icmp_to_container_unknown_src_miss_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, PODIP_ICMP_REQ);
	return 0;
}

SETUP("tc", "08_icmp_to_container_unknown_src_miss_dst")
int privnet_icmp_to_container_unknown_src_miss_dst_setup(struct __ctx_buff *ctx)
{
	/* no entry for dst */
	ctx_store_meta(ctx, CB_FROM_TUNNEL, 1);

	set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	return pod_receive_packet_by_tailcall(ctx);
}

CHECK("tc", "08_icmp_to_container_unknown_src_miss_dst")
int privnet_icmp_to_container_unknown_src_miss_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, DROP_UNROUTABLE); /* drop check*/

	assert_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);

	test_finish();
}

/* IPv6 test cases */
const __u8 *BUF(__UNUSED__) = NULL;

static __always_inline int privnet_icmp6_ns_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4, &lxc_privnet_ipv6);
	privnet_v6_add_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN, SUBNET_ID);
	privnet_v6_add_endpoint_entry(NET_ID, SUBNET_ID,
				      (const union v6addr *)V6_NET_IP_1,
				      (const union v6addr *)V6_POD_IP_1);
	privnet_v6_add_endpoint_entry(NET_ID, SUBNET_ID,
				      (const union v6addr *)V6_NET_IP_2,
				      (const union v6addr *)V6_POD_IP_2);

	return pod_send_packet(ctx);
}

#define PRIVNET_ICMP6_NS_CHECK(CTX, TEST_NAME, STATUS_CODE, NA_BUF_NAME)	\
	do {									\
		test_init();							\
										\
		assert_status_code(CTX, (STATUS_CODE));				\
		if (STATUS_CODE == TC_ACT_REDIRECT) {				\
			ASSERT_CTX_BUF_OFF(TEST_NAME, "Ether", CTX,		\
				sizeof(__u32), NA_BUF_NAME,			\
				sizeof(BUF(NA_BUF_NAME)));			\
		}								\
										\
		privnet_v6_del_endpoint_entry(NET_ID, SUBNET_ID,		\
			(const union v6addr *)V6_NET_IP_1,			\
			(const union v6addr *)V6_POD_IP_1);			\
		privnet_v6_del_endpoint_entry(NET_ID, SUBNET_ID,		\
			(const union v6addr *)V6_NET_IP_2,			\
			(const union v6addr *)V6_POD_IP_2);			\
		privnet_v6_del_subnet_entry(NET_ID, SUBNET_V6, SUBNET_V6_LEN);  \
		privnet_del_device_entry(IFINDEX);				\
										\
		test_finish();							\
	} while (0)

/* Neighbor solicitation response generated for link local address */
PKTGEN("tc", "09_icmp6_from_container_neighbor_solicitation_link_local")
int privnet_icmp6_from_container_neighbor_solicitation_link_local_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, LXC_ICMP6_NS_LL);
	return 0;
}

SETUP("tc", "09_icmp6_from_container_neighbor_solicitation_link_local")
int privnet_icmp6_from_container_neighbor_solicitation_link_local_setup(struct __ctx_buff *ctx)
{
	return privnet_icmp6_ns_setup(ctx);
}

CHECK("tc", "09_icmp6_from_container_neighbor_solicitation_link_local")
int privnet_icmp6_from_container_neighbor_solicitation_link_local_check(struct __ctx_buff *ctx)
{
	PRIVNET_ICMP6_NS_CHECK(ctx,
			       "09_icmp6_from_container_neighbor_solicitation_link_local",
			       TC_ACT_REDIRECT, LXC_ICMP6_NA_LL
	);
}

/* Neighbor solicitation response generated for endpoint address */
PKTGEN("tc", "10_icmp6_from_container_neighbor_solicitation_ep_match")
int privnet_icmp6_from_container_neighbor_solicitation_ep_match_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, LXC_ICMP6_NS_EP1);
	return 0;
}

SETUP("tc", "10_icmp6_from_container_neighbor_solicitation_ep_match")
int privnet_icmp6_from_container_neighbor_solicitation_ep_match_setup(struct __ctx_buff *ctx)
{
	return privnet_icmp6_ns_setup(ctx);
}

CHECK("tc", "10_icmp6_from_container_neighbor_solicitation_ep_match")
int privnet_icmp6_from_container_neighbor_solicitation_ep_match_check(struct __ctx_buff *ctx)
{
	PRIVNET_ICMP6_NS_CHECK(ctx,
			       "10_icmp6_from_container_neighbor_solicitation_ep_match",
			       TC_ACT_REDIRECT, LXC_ICMP6_NA_EP1
	);
}

/* Neighbor solicitation response should not be generated for endpoint address not in FIB map */
PKTGEN("tc", "11_icmp6_from_container_neighbor_solicitation_ep_no_match")
int privnet_icmp6_from_container_neighbor_solicitation_ep_no_match_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, LXC_ICMP6_NS_EP2);
	return 0;
}

SETUP("tc", "11_icmp6_from_container_neighbor_solicitation_ep_no_match")
int privnet_icmp6_from_container_neighbor_solicitation_ep_no_match_setup(struct __ctx_buff *ctx)
{
	return privnet_icmp6_ns_setup(ctx);
}

CHECK("tc", "11_icmp6_from_container_neighbor_solicitation_ep_no_match")
int privnet_icmp6_from_container_neighbor_solicitation_ep_no_match_check(struct __ctx_buff *ctx)
{
	PRIVNET_ICMP6_NS_CHECK(ctx,
			       "10_icmp6_from_container_neighbor_solicitation_ep_no_match",
			       TC_ACT_SHOT, __UNUSED__
	);
}

/* Neighbor solicitation response should not be generated for the self endpoint address */
PKTGEN("tc", "12_icmp6_from_container_neighbor_solicitation_self")
int privnet_icmp6_from_container_neighbor_solicitation_self_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, LXC_ICMP6_NS_SELF);
	return 0;
}

SETUP("tc", "12_icmp6_from_container_neighbor_solicitation_self")
int privnet_icmp6_from_container_neighbor_solicitation_self_setup(struct __ctx_buff *ctx)
{
	return privnet_icmp6_ns_setup(ctx);
}

CHECK("tc", "12_icmp6_from_container_neighbor_solicitation_self")
int privnet_icmp6_from_container_neighbor_solicitation_self_check(struct __ctx_buff *ctx)
{
	PRIVNET_ICMP6_NS_CHECK(ctx,
			       "12_icmp6_from_container_neighbor_solicitation_self",
			       TC_ACT_SHOT, __UNUSED__
	);
}

PKTGEN("tc", "13_icmp_from_container_missing_net_id")
int privnet_icmp_from_container_missing_net_id_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, NETIP_ICMP_REQ);
	return 0;
}

SETUP("tc", "13_icmp_from_container_missing_net_id")
int privnet_icmp_from_container_missing_net_id_setup(struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_UNROUTABLE,
		.dir = METRIC_EGRESS,
	};
	map_delete_elem(&cilium_metrics, &key);

	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	return pod_send_packet(ctx);
}

CHECK("tc", "13_icmp_from_container_missing_net_id")
int privnet_icmp_from_container_missing_net_id_check(struct __ctx_buff *ctx)
{
	struct metrics_value *entry = NULL;
	struct metrics_key key = {
		.reason = (__u8)-DROP_UNROUTABLE,
		.dir = METRIC_EGRESS,
	};
	__u64 count = 1;

	test_init();

	assert_status_code(ctx, CTX_ACT_DROP); /* drop check */

	/* check reason for drop */
	entry = map_lookup_elem(&cilium_metrics, &key);
	if (!entry)
		test_fatal("metrics entry not found");

	assert_metrics_count(key, count);

	assert_privnet_net_ids(PRIVNET_UNKNOWN_NET_ID, PRIVNET_UNKNOWN_NET_ID);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	test_finish();
}

/* ARP request for the privnet IPv4 should be dropped to allow DHCP renewals.
 * If we don't drop them DHCP clients will decline the IP as they detect a conflict
 * when the "arping" for the offered address.
 */

PKTGEN("tc", "14_arp_from_container_privnet_ip_match")
int privnet_arp_from_container_privnet_ip_mismatch_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, NETIP_ARP_REQ);
	return 0;
}

SETUP("tc", "14_arp_from_container_privnet_ip_match")
int privnet_arp_from_container_privnet_ip_mismatch_setup(struct __ctx_buff *ctx)
{
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4_other,
				 &lxc_privnet_ipv6);
	return pod_send_packet(ctx);
}

CHECK("tc", "14_arp_from_container_privnet_ip_match")
int privnet_arp_from_container_privnet_ip_mismatch_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, CTX_ACT_DROP);

	privnet_del_device_entry(IFINDEX);
	test_finish();
}

PKTGEN("tc", "15_dhcp_from_container_redirect")
int privnet_dhcp_from_container_redirect_pktgen(struct __ctx_buff *ctx)
{
	return build_privnet_dhcp_request_to(ctx, dhcp_bcast_mac,
					     IPV4(255, 255, 255, 255));
}

SETUP("tc", "15_dhcp_from_container_redirect")
int privnet_dhcp_from_container_redirect_setup(struct __ctx_buff *ctx)
{
	redirect_target_ifindex = 0;
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4,
				 &lxc_privnet_ipv6);
	return pod_send_packet(ctx);
}

CHECK("tc", "15_dhcp_from_container_redirect")
int privnet_dhcp_from_container_redirect_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_REDIRECT);
	if (redirect_target_ifindex != CILIUM_DHCP_IFINDEX)
		test_fatal("unexpected redirect ifindex (expected %d, got %d)",
			   CILIUM_DHCP_IFINDEX, redirect_target_ifindex);

	privnet_del_device_entry(IFINDEX);
	test_finish();
}

PKTGEN("tc", "16_dhcp_from_container_unicast_redirect")
int privnet_dhcp_from_container_unicast_redirect_pktgen(struct __ctx_buff *ctx)
{
	return build_privnet_dhcp_request_to(ctx, (__u8 *)mac_two, V4_NET_IP_1);
}

SETUP("tc", "16_dhcp_from_container_unicast_redirect")
int privnet_dhcp_from_container_unicast_redirect_setup(struct __ctx_buff *ctx)
{
	redirect_target_ifindex = 0;
	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4,
				 &lxc_privnet_ipv6);

	return pod_send_packet(ctx);
}

CHECK("tc", "16_dhcp_from_container_unicast_redirect")
int privnet_dhcp_from_container_unicast_redirect_check(struct __ctx_buff *ctx)
{
	test_init();

	assert_status_code(ctx, TC_ACT_REDIRECT);
	if (redirect_target_ifindex != CILIUM_DHCP_IFINDEX)
		test_fatal("unexpected redirect ifindex (expected %d, got %d)",
			   CILIUM_DHCP_IFINDEX, redirect_target_ifindex);

	privnet_del_device_entry(IFINDEX);
	test_finish();
}

PKTGEN("tc", "17_tcp_from_container_spoofed_drop")
int privnet_tcp_from_container_spoofed_drop_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, NETIP_TCP_SYN);

	return 0;
}

SETUP("tc", "17_tcp_from_container_spoofed_drop")
int privnet_tcp_from_container_spoofed_drop_setup(struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_UNROUTABLE,
		.dir = METRIC_EGRESS,
	};
	map_delete_elem(&cilium_metrics, &key);

	privnet_add_device_entry(IFINDEX, NET_ID, &lxc_privnet_ipv4_other, &lxc_privnet_ipv6);
	privnet_v4_add_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN, SUBNET_ID);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	return pod_send_packet(ctx);
}

CHECK("tc", "17_tcp_from_container_spoofed_drop")
int privnet_tcp_from_container_spoofed_drop_check(struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_UNROUTABLE,
		.dir = METRIC_EGRESS,
	};
	struct metrics_value *entry = NULL;
	__u64 count = 1;

	test_init();

	/* dropped due to source address mismatch */
	assert_status_code(ctx, CTX_ACT_DROP);

	/* check reason for drop */
	entry = map_lookup_elem(&cilium_metrics, &key);
	if (!entry)
		test_fatal("metrics entry not found");

	assert_privnet_net_ids(NET_ID, NET_ID);

	assert_metrics_count(key, count);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_subnet_entry(NET_ID, SUBNET_V4, SUBNET_V4_LEN);
	privnet_del_device_entry(IFINDEX);

	test_finish();
}
