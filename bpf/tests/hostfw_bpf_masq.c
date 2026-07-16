// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4			1
#define ENABLE_MASQUERADE_IPV4		1
#define ENABLE_HOST_FIREWALL		1

#define POD_SEC_IDENTITY		112233

#define NODE_IP				v4_node_one
#define NODE_PORT			bpf_htons(50001)

#define SERVER_IP			v4_ext_one
#define SERVER_PORT			bpf_htons(80)

static volatile const __u8 *node_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;

#include "lib/bpf_host.h"

ASSIGN_CONFIG(bool, enable_conntrack_accounting, true)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/policy.h"

/* Send a request for a non-transparent proxy connection to another endpoint.
 * Use NODE_IP as source IP, and mark the packet with MARK_MAGIC_PROXY_EGRESS.
 *
 * Also send a reply.
 *
 * The egress path should create a CT entry, but apply no egress network policy.
 * The ingress path should apply no ingress network policy.
 */
PKTGEN("tc", "hostfw_ipv4_bpf_masq_proxy_01")
int hostfw_ipv4_bpf_masq_proxy_01_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	udp = pktgen__push_ipv4_udp_packet(&builder,
					   (__u8 *)node_mac, (__u8 *)server_mac,
					   NODE_IP, SERVER_IP,
					   NODE_PORT, SERVER_PORT);
	if (!udp)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "hostfw_ipv4_bpf_masq_proxy_01")
int hostfw_ipv4_bpf_masq_proxy_01_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(NODE_IP, 0, 0, ENDPOINT_F_HOST, HOST_ID,
			      0, (__u8 *)node_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(NODE_IP, 0, HOST_ID, 0, 0);
	ipcache_v4_add_world_entry();

	set_identity_mark(ctx, POD_SEC_IDENTITY, MARK_MAGIC_PROXY_EGRESS);

	return netdev_send_packet(ctx);
}

CHECK("tc", "hostfw_ipv4_bpf_masq_proxy_01")
int hostfw_ipv4_bpf_masq_proxy_01_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	endpoint_v4_del_entry(NODE_IP);

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	/* Check whether HostFW created a CT entry */
	struct ipv4_ct_tuple tuple = {
		.daddr   = NODE_IP,
		.saddr   = SERVER_IP,
		.dport   = SERVER_PORT,
		.sport   = NODE_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	assert(ct_entry->packets == 1);

	test_finish();
}

PKTGEN("tc", "hostfw_ipv4_bpf_masq_proxy_02")
int hostfw_ipv4_bpf_masq_proxy_02_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	udp = pktgen__push_ipv4_udp_packet(&builder,
					   (__u8 *)server_mac, (__u8 *)node_mac,
					   SERVER_IP, NODE_IP,
					   SERVER_PORT, NODE_PORT);
	if (!udp)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "hostfw_ipv4_bpf_masq_proxy_02")
int hostfw_ipv4_bpf_masq_proxy_02_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK("tc", "hostfw_ipv4_bpf_masq_proxy_02")
int hostfw_ipv4_bpf_masq_proxy_02_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	/* Check whether HostFW updated the CT entry */
	struct ipv4_ct_tuple tuple = {
		.daddr   = NODE_IP,
		.saddr   = SERVER_IP,
		.dport   = SERVER_PORT,
		.sport   = NODE_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	assert(ct_entry->packets == 2);

	test_finish();
}

/* We leave on purpose CONFIG(enable_extended_ip_protocols) set to false
 * to test that HostFW enforces policies for such traffic types (failing with
 * a ct lookup) only when explicitly carrying HOST_ID.
 */

/* This one tests an egress packet with an unknown CT protocol (e.g, IGMP)
 * carrying HOST_ID (host-generated).
 * We expect conntrack lookup to fail, and the packet to be dropped with
 * the DROP_CT_UNKNOWN_PROTO error.
 */
PKTGEN("tc", "hostfw_ipv4_bpf_masq_extended_protocol")
int hostfw_ipv4_bpf_masq_extended_protocol_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct iphdr *l3;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv4_packet(&builder,
				      (__u8 *)node_mac, (__u8 *)server_mac,
				      NODE_IP, SERVER_IP);

	if (!l3)
		return TEST_ERROR;

	l3->protocol = IPPROTO_IGMP;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "hostfw_ipv4_bpf_masq_extended_protocol")
int hostfw_ipv4_bpf_masq_extended_protocol_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(NODE_IP, 0, 0, ENDPOINT_F_HOST, HOST_ID,
			      0, (__u8 *)node_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(NODE_IP, 0, HOST_ID, 0, 0);
	ipcache_v4_add_world_entry();

	set_identity_mark(ctx, 0, MARK_MAGIC_HOST);

	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "hostfw_ipv4_bpf_masq_extended_protocol")
int hostfw_ipv4_bpf_masq_extended_protocol_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct metrics_key key = {
		.dir = METRIC_EGRESS,
		.reason = (__u8)-DROP_CT_UNKNOWN_PROTO,
	};
	__u64 count = 1;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_DROP);

	assert_metrics_count(key, count);

	test_finish();
}

/* This one tests an egress packet with an unknown CT protocol (e.g, IGMP)
 * carrying UNKNOWN_ID (e.g., kernel-generated multicast join message).
 * We expect conntrack lookup to fail, but we tolerate it and skip policies.
 */
PKTGEN("tc", "hostfw_ipv4_bpf_masq_unknown_id_extended_protocol")
int hostfw_ipv4_bpf_masq_unknown_id_extended_protocol_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct iphdr *l3;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv4_packet(&builder,
				      (__u8 *)server_mac, (__u8 *)node_mac,
				      NODE_IP, SERVER_IP);
	if (!l3)
		return TEST_ERROR;

	l3->protocol = IPPROTO_IGMP;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "hostfw_ipv4_bpf_masq_unknown_id_extended_protocol")
int hostfw_ipv4_bpf_masq_unknown_id_extended_protocol_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(NODE_IP, 0, 0, ENDPOINT_F_HOST, HOST_ID,
			      0, (__u8 *)node_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(NODE_IP, 0, HOST_ID, 0, 0);
	ipcache_v4_add_world_entry();

	ctx->mark = 0;

	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "hostfw_ipv4_bpf_masq_unknown_id_extended_protocol")
int hostfw_ipv4_bpf_masq_unknown_id_extended_protocol_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	test_finish();
}
