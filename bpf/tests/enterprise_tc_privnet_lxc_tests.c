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

#include "lib/bpf_lxc.h"

/* Include test helpers */
#include "tests/lib/enterprise_privnet.h"
#include "tests/lib/policy.h"

/* Enable privnet */
ASSIGN_CONFIG(bool, privnet_enable, true)
ASSIGN_CONFIG(__u16, privnet_network_id, NET_ID)
ASSIGN_CONFIG(__u32, privnet_unknown_sec_id, 99) /* tunnel id 99 is reserved for unknown privnet flow */
ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_two_addr}) /* set lxc mac */

PKTGEN("tc", "01_icmp_from_container_nat_src_dst")
int privnet_icmp_from_container_nat_src_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, NETIP_ICMP_REQ);
	return 0;
}

SETUP("tc", "01_icmp_from_container_nat_src_dst")
int privnet_icmp_from_container_nat_src_dst_setup(struct __ctx_buff *ctx)
{
	privnet_v4_add_endpoint_entry(NET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, V4_NET_IP_2, V4_POD_IP_2);

	/* allow traffic from endpoints */
	policy_add_egress_allow_all_entry();

	pod_send_packet(ctx);
	return TEST_ERROR;
}

CHECK("tc", "01_icmp_from_container_nat_src_dst")
int privnet_icmp_from_container_nat_src_dst_check(struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_icmp_from_container_nat_src_dst", "IP", ctx,
			   sizeof(__u32), PODIP_ICMP_REQ,
			   sizeof(BUF(PODIP_ICMP_REQ)));

	privnet_v4_del_endpoint_entry(NET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, V4_NET_IP_2, V4_POD_IP_2);

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
	privnet_v4_add_endpoint_entry(NET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, V4_NET_IP_2, V4_POD_IP_2);

	/* allow traffic from endpoints */
	policy_add_egress_allow_all_entry();

	pod_send_packet(ctx);
	return TEST_ERROR;
}

CHECK("tc", "02_tcp_from_container_nat_src_dst")
int privnet_tcp_from_container_nat_src_dst_check(struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_tcp_from_container_nat_src_dst", "IP", ctx,
			   sizeof(__u32), PODIP_TCP_SYN,
			   sizeof(BUF(PODIP_TCP_SYN)));

	privnet_v4_del_endpoint_entry(NET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, V4_NET_IP_2, V4_POD_IP_2);

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
	privnet_v4_add_endpoint_entry(NET_ID, V4_NET_IP_1, V4_POD_IP_1); /* source entry */
	privnet_v4_add_subnet_route(NET_ID, V4_NET_IP_2, INB_IP); /* destination entry */

	/* allow traffic from endpoints */
	policy_add_egress_allow_all_entry();

	pod_send_packet(ctx);
	return TEST_ERROR;
}

CHECK("tc", "03_icmp_from_container_nat_src_route_dst")
int privnet_icmp_from_container_nat_src_route_dst_check(struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_REDIRECT); /* redirected via unknown flow */

	/* check inner packet headers, dst should remain untranslated */
	ASSERT_CTX_BUF_OFF("privnet_icmp_from_container_nat_src_route_dst", "IP", ctx,
			   sizeof(__u32), UNKNOWN_ICMP_REQ,
			   sizeof(BUF(UNKNOWN_ICMP_REQ)));

	privnet_v4_del_endpoint_entry(NET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_route(NET_ID, V4_NET_IP_2);
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

	privnet_v4_add_endpoint_entry(NET_ID, V4_NET_IP_1, V4_POD_IP_1); /* only source entry */

	/* allow traffic from endpoints */
	policy_add_egress_allow_all_entry();

	pod_send_packet(ctx);
	return TEST_ERROR;
}

CHECK("tc", "04_icmp_from_container_nat_src_miss_dst")
int privnet_icmp_from_container_nat_src_miss_dst_check(struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct metrics_value *entry = NULL;
	struct metrics_key key = {};

	test_init();
	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_DROP); /* drop check*/

	/* check reason for drop */
	key.reason = (__u8)-DROP_UNROUTABLE;
	key.dir = METRIC_EGRESS;
	entry = map_lookup_elem(&cilium_metrics, &key);
	if (!entry)
		test_fatal("metrics entry not found");

	__u64 count = 1;

	assert_metrics_count(key, count);
	privnet_v4_del_endpoint_entry(NET_ID, V4_NET_IP_1, V4_POD_IP_1);
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
	privnet_v4_add_endpoint_entry(NET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, V4_NET_IP_2, V4_POD_IP_2);

	policy_add_ingress_allow_entry(0, 0, 0);
	pod_receive_packet_by_tailcall(ctx);
	return TEST_ERROR;
}

CHECK("tc", "05_icmp_to_container_nat_src_dst")
int privnet_icmp_to_container_nat_src_dst_check(struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_OK);

	BUF_DECL(EXPECTED_NETIP_ICMP_REQ, privnet_net_ip_icmp_req);
	ASSERT_CTX_BUF_OFF("privnet_icmp_to_container_nat_src_dst", "IP", ctx,
			   sizeof(__u32), EXPECTED_NETIP_ICMP_REQ,
			   sizeof(BUF(EXPECTED_NETIP_ICMP_REQ)));

	privnet_v4_del_endpoint_entry(NET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, V4_NET_IP_2, V4_POD_IP_2);

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
	privnet_v4_add_endpoint_entry(NET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, V4_NET_IP_2, V4_POD_IP_2);

	policy_add_ingress_allow_entry(0, 0, 0);
	pod_receive_packet_by_tailcall(ctx);
	return TEST_ERROR;
}

CHECK("tc", "06_tcp_to_container_nat_src_dst")
int privnet_tcp_to_container_nat_src_dst_check(struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_tcp_to_container_nat_src_dst", "IP", ctx,
			   sizeof(__u32), NETIP_TCP_SYN,
			   sizeof(BUF(NETIP_TCP_SYN)));

	privnet_v4_del_endpoint_entry(NET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, V4_NET_IP_2, V4_POD_IP_2);

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
	/* dst is known, no entry for src */
	privnet_v4_add_endpoint_entry(NET_ID, V4_NET_IP_2, V4_POD_IP_2);

	ctx_store_meta(ctx, CB_FROM_TUNNEL, 1);
	pod_receive_packet_by_tailcall(ctx);
	return TEST_ERROR;
}

CHECK("tc", "07_icmp_to_container_unknown_src_nat_dst")
int privnet_icmp_to_container_unknown_src_nat_dst_check(struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_OK);

	ASSERT_CTX_BUF_OFF("privnet_icmp_to_container_unknown_src_nat_dst", "IP", ctx,
			   sizeof(__u32), UNKNOWN_ICMP_REQ,
			   sizeof(BUF(UNKNOWN_ICMP_REQ)));

	privnet_v4_del_endpoint_entry(NET_ID, V4_NET_IP_2, V4_POD_IP_2);
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
	pod_receive_packet_by_tailcall(ctx);
	return TEST_ERROR;
}

CHECK("tc", "08_icmp_to_container_unknown_src_miss_dst")
int privnet_icmp_to_container_unknown_src_miss_dst_check(struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	int *status_code;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == DROP_UNROUTABLE); /* drop check*/

	test_finish();
}

/* IPv6 test cases */

/* Neighbor solicitation response generated for link local address */
PKTGEN("tc", "09_icmp6_from_container_neighbor_solicitation")
int privnet_icmp6_from_container_neighbor_solicitation_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, LXC_ICMP6_NS);
	return 0;
}

SETUP("tc", "09_icmp6_from_container_neighbor_solicitation")
int privnet_icmp6_from_container_neighbor_solicitation_setup(struct __ctx_buff *ctx)
{
	pod_send_packet(ctx);
	return TEST_ERROR;
}

CHECK("tc", "09_icmp6_from_container_neighbor_solicitation")
int privnet_icmp6_from_container_neighbor_solicitation_check(struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_REDIRECT); /* packet is sent back to lxc */

	ASSERT_CTX_BUF_OFF("icmp6_from_container_neighbor_solicitation", "Ether", ctx,
			   sizeof(__u32), LXC_ICMP6_NA,
			   sizeof(BUF(LXC_ICMP6_NA)));

	test_finish();
}
