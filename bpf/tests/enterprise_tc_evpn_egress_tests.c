// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/config/node.h>

#include "common.h"
#include "pktgen.h"
#include <lib/common.h>

static int last_redirect_ifindex;
static struct bpf_tunnel_key last_tunnel_key;

#undef ctx_redirect
#define ctx_redirect mock_ctx_redirect
static __always_inline int
mock_ctx_redirect(const struct __sk_buff __maybe_unused *ctx, int ifindex,
		  __u32 __maybe_unused flags)
{
	last_redirect_ifindex = ifindex;
	return CTX_ACT_REDIRECT;
}

#undef ctx_set_tunnel_key
#define ctx_set_tunnel_key mock_ctx_set_tunnel_key
static __always_inline int
mock_ctx_set_tunnel_key(const struct __sk_buff __maybe_unused *ctx,
			struct bpf_tunnel_key *tunnel_key, __u32 size,
			__u32 __maybe_unused flags)
{
	if (size != TUNNEL_KEY_WITHOUT_SRC_IP)
		return -EINVAL;

	memcpy(&last_tunnel_key, tunnel_key, TUNNEL_KEY_WITHOUT_SRC_IP);

	return 0;
}

static __always_inline void
cleanup_test_state(struct ethhdr *eth)
{
	last_redirect_ifindex = 0;
	memset(&last_tunnel_key, 0, sizeof(last_tunnel_key));
	memset(eth->h_dest, 0, ETH_ALEN);
	memset(eth->h_source, 0, ETH_ALEN);
}

#include <lib/enterprise_evpn.h>
#include "enterprise_evpn_common.h"

/* Datapath dummy config for tests */
#define ENABLE_IPV4
#define ENABLE_IPV6

/* Enable debug output */
#define DEBUG

#include <bpf/config/node.h>

#include "tests/lib/enterprise_evpn.h"

/* Enable configurations */
ASSIGN_CONFIG(bool, evpn_enable, true)
ASSIGN_CONFIG(__u32, evpn_device_ifindex, 123)
ASSIGN_CONFIG(union macaddr, evpn_device_mac, {.addr = mac_two_addr })

CHECK("tc", "evpn_encap_and_redirect4")
int evpn_encap_and_redirect4_check(struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ethhdr *eth;
	int ret;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};

	test_init();

	if (data + sizeof(*eth) > data_end)
		test_fatal("packet too short for ethhdr");

	eth = data;

	cleanup_test_state(eth);

	evpn_setup_fib();

	TEST("evpn_encap_and_redirect4 match", {
		ret = evpn_encap_and_redirect4(ctx, 1, 1, EVPN_V4_ADDR0, &trace);
		if (ret != TC_ACT_REDIRECT)
			test_error("Expect TC_ACT_REDIRECT, but got %d", ret);

		if (last_redirect_ifindex != 123)
			test_error("Expect redirect ifindex 123, but got %d",
				   last_redirect_ifindex);

		if (memcmp((void *)eth->h_dest, (void *)mac_one, ETH_ALEN) != 0)
			test_error("Unexpected destination MAC");

		if (memcmp((void *)eth->h_source, (void *)mac_two, ETH_ALEN) != 0)
			test_error("Unexpected source MAC");

		if (last_tunnel_key.tunnel_id != 100)
			test_error("Expect tunnel_id 100, but got %u", last_tunnel_key.tunnel_id);

		if (last_tunnel_key.remote_ipv4 != bpf_ntohl(v4_node_one))
			test_error("Unexpected remote_ipv4");

		cleanup_test_state(eth);
	});

	TEST("evpn_encap_and_redirect4 no match", {
		ret = evpn_encap_and_redirect4(ctx, 2, 2, EVPN_V4_ADDR1, &trace);
		if (ret != DROP_UNROUTABLE)
			test_error("Expect DROP_UNROUTABLE, but got %d", ret);

		cleanup_test_state(eth);
	});

	evpn_cleanup_fib();

	test_finish();

	return 0;
}

/* We needed to decouple this case from evpn_encap_and_redirect4_check
 * because it hits the complexity limit.
 */
CHECK("tc", "evpn_encap_and_redirect4_ipv6_nexthop")
int evpn_encap_and_redirect4_ipv6_nexthop_check(struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ethhdr *eth;
	int ret;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};

	test_init();

	if (data + sizeof(*eth) > data_end)
		test_fatal("packet too short for ethhdr");

	eth = data;

	cleanup_test_state(eth);

	evpn_setup_fib();

	TEST("evpn_encap_and_redirect4 IPv6 nexthop", {
		ret = evpn_encap_and_redirect4(ctx, 1, 1, EVPN_V4_ADDR2, &trace);
		if (ret != TC_ACT_REDIRECT)
			test_error("Expect TC_ACT_REDIRECT, but got %d", ret);

		if (last_redirect_ifindex != 123)
			test_error("Expect redirect ifindex 123, but got %d",
				   last_redirect_ifindex);

		if (memcmp((void *)eth->h_dest, (void *)mac_one, ETH_ALEN) != 0)
			test_error("Unexpected destination MAC");

		if (memcmp((void *)eth->h_source, (void *)mac_two, ETH_ALEN) != 0)
			test_error("Unexpected source MAC");

		if (last_tunnel_key.tunnel_id != 300)
			test_error("Expect tunnel_id 300, but got %u", last_tunnel_key.tunnel_id);

		if (memcmp(last_tunnel_key.remote_ipv6, (const void *)&v6_node_one,
			   sizeof(v6_node_one)) != 0)
			test_error("Unexpected remote_ipv6");

		cleanup_test_state(eth);
	});

	evpn_cleanup_fib();

	test_finish();

	return 0;
}

CHECK("tc", "evpn_encap_and_redirect6")
int evpn_encap_and_redirect6_check(struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ethhdr *eth;
	int ret;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};

	test_init();

	if (data + sizeof(*eth) > data_end)
		test_fatal("packet too short for ethhdr");

	eth = data;

	cleanup_test_state(eth);

	evpn_setup_fib();

	TEST("evpn_encap_and_redirect6 match", {
		union v6addr expected_remote_ipv6 = { .addr = v6_node_one_addr };

		ret = evpn_encap_and_redirect6(ctx, 1, 1, EVPN_V6_ADDR0, &trace);
		if (ret != TC_ACT_REDIRECT)
			test_error("Expect TC_ACT_REDIRECT, but got %d", ret);

		if (last_redirect_ifindex != 123)
			test_error("Expect redirect ifindex 123, but got %d",
				   last_redirect_ifindex);

		if (memcmp((void *)eth->h_dest, (void *)mac_one, ETH_ALEN) != 0)
			test_error("Unexpected destination MAC");

		if (memcmp((void *)eth->h_source, (void *)mac_two, ETH_ALEN) != 0)
			test_error("Unexpected source MAC");

		if (last_tunnel_key.tunnel_id != 100)
			test_error("Expect tunnel_id 100, but got %u", last_tunnel_key.tunnel_id);

		if (memcmp(last_tunnel_key.remote_ipv6, &expected_remote_ipv6,
			   sizeof(expected_remote_ipv6)) != 0)
			test_error("Unexpected remote_ipv6");

		cleanup_test_state(eth);
	});

	TEST("evpn_encap_and_redirect6 no match", {
		ret = evpn_encap_and_redirect6(ctx, 2, 2, EVPN_V6_ADDR1, &trace);
		if (ret != DROP_UNROUTABLE)
			test_error("Expect DROP_UNROUTABLE, but got %d", ret);

		cleanup_test_state(eth);
	});

	evpn_cleanup_fib();

	test_finish();

	return 0;
}

/* We needed to decouple this case from evpn_encap_and_redirect6_check
 * because it hits the complexity limit.
 */
CHECK("tc", "evpn_encap_and_redirect6_ipv4_nexthop")
int evpn_encap_and_redirect6_ipv4_nexthop_check(struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ethhdr *eth;
	int ret;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};

	test_init();

	if (data + sizeof(*eth) > data_end)
		test_fatal("packet too short for ethhdr");

	eth = data;

	cleanup_test_state(eth);

	evpn_setup_fib();

	TEST("evpn_encap_and_redirect6 IPv4 nexthop", {
		ret = evpn_encap_and_redirect6(ctx, 1, 1, EVPN_V6_ADDR2, &trace);
		if (ret != TC_ACT_REDIRECT)
			test_error("Expect TC_ACT_REDIRECT, but got %d", ret);

		if (last_redirect_ifindex != 123)
			test_error("Expect redirect ifindex 123, but got %d",
				   last_redirect_ifindex);

		if (memcmp((void *)eth->h_dest, (void *)mac_one, ETH_ALEN) != 0)
			test_error("Unexpected destination MAC");

		if (memcmp((void *)eth->h_source, (void *)mac_two, ETH_ALEN) != 0)
			test_error("Unexpected source MAC");

		if (last_tunnel_key.tunnel_id != 300)
			test_error("Expect tunnel_id 300, but got %u", last_tunnel_key.tunnel_id);

		if (last_tunnel_key.remote_ipv4 != bpf_ntohl(v4_node_one))
			test_error("Unexpected remote_ipv4");

		cleanup_test_state(eth);
	});

	evpn_cleanup_fib();

	test_finish();

	return 0;
}
