// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_EGRESS_GATEWAY_HA
#define ENABLE_MASQUERADE_IPV4		1
#define ENCAP_IFINDEX 0

#include "lib/bpf_host.h"

#include "lib/egressgw.h"
#include "lib/egressgw_ha.h"
#include "lib/endpoint.h"
#include "lib/ipcache.h"

/* Test that a packet matching an egress gateway policy on the to-netdev
 * program gets redirected to the gateway node.
 */
PKTGEN("tc", "tc_egressgw_ha_redirect1")
int egressgw_ha_redirect1_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_HA_REDIRECT,
		});
}

SETUP("tc", "tc_egressgw_ha_redirect1")
int egressgw_ha_redirect1_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_world_entry();
	create_ct_entry(ctx, client_port(TEST_HA_REDIRECT));
	add_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, 1,
				     { GATEWAY_NODE_IP }, EGRESS_IP, 0);

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_egressgw_ha_redirect1")
int egressgw_ha_redirect1_check(const struct __ctx_buff *ctx)
{
	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = TC_ACT_REDIRECT,
	});

	del_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24);

	return ret;
}

/* Test that a second packet for the same connection is still redirected
 * to the gateway node, even when the gateway is no longer active.
 */
PKTGEN("tc", "tc_egressgw_ha_redirect2_inactive_gw")
int egressgw_ha_redirect2_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_HA_REDIRECT,
		});
}

SETUP("tc", "tc_egressgw_ha_redirect2_inactive_gw")
int egressgw_ha_redirect2_setup(struct __ctx_buff *ctx)
{
	add_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, 0,
				     { 0 }, EGRESS_IP, 0);

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_egressgw_ha_redirect2_inactive_gw")
int egressgw_ha_redirect3_check(const struct __ctx_buff *ctx)
{
	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = TC_ACT_REDIRECT,
	});

	del_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24);

	return ret;
}

/* Test that a packet matching an excluded CIDR egress gateway policy on the
 * to-netdev program does not get redirected to the gateway node.
 */
PKTGEN("tc", "tc_egressgw_ha_skip_excluded_cidr_redirect")
int egressgw_ha_skip_excluded_cidr_redirect_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_HA_REDIRECT_EXCL_CIDR,
		});
}

SETUP("tc", "tc_egressgw_ha_skip_excluded_cidr_redirect")
int egressgw_ha_skip_excluded_cidr_redirect_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_world_entry();
	create_ct_entry(ctx, client_port(TEST_HA_REDIRECT_EXCL_CIDR));
	add_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, 1,
				     { GATEWAY_NODE_IP }, EGRESS_IP, 0);
	add_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP, 32, 1,
				     { EGRESS_GATEWAY_EXCLUDED_CIDR }, EGRESS_IP, 0);

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_egressgw_ha_skip_excluded_cidr_redirect")
int egressgw_ha_skip_excluded_cidr_redirect_check(const struct __ctx_buff *ctx)
{
	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = TC_ACT_OK,
	});

	del_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24);
	del_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP, 32);

	return ret;
}

/* Test that a packet matching an egress gateway policy without a gateway on the
 * to-netdev program does not get redirected to the gateway node.
 */
PKTGEN("tc", "tc_egressgw_ha_skip_no_gateway_redirect")
int egressgw_skip_no_gateway_redirect_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_HA_REDIRECT_SKIP_NO_GATEWAY,
		});
}

SETUP("tc", "tc_egressgw_ha_skip_no_gateway_redirect")
int egressgw_skip_no_gateway_redirect_setup(struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_NO_EGRESS_GATEWAY,
		.dir = METRIC_EGRESS,
	};

	map_delete_elem(&cilium_metrics, &key);
	ipcache_v4_add_world_entry();
	create_ct_entry(ctx, client_port(TEST_HA_REDIRECT_SKIP_NO_GATEWAY));
	add_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP, 32, 0, {},
				     EGRESS_IP, 0);

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_egressgw_ha_skip_no_gateway_redirect")
int egressgw_ha_skip_no_gateway_redirect_check(const struct __ctx_buff *ctx)
{
	struct metrics_value *entry = NULL;
	struct metrics_key key = {};

	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = CTX_ACT_DROP,
	});
	if (ret != TEST_PASS)
		return ret;

	test_init();

	key.reason = (__u8)-DROP_NO_EGRESS_GATEWAY;
	key.dir = METRIC_EGRESS;
	entry = map_lookup_elem(&cilium_metrics, &key);
	if (!entry)
		test_fatal("metrics entry not found");

	__u64 count = 1;

	assert_metrics_count(key, count);

	del_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP, 32);

	test_finish();
}

/* Test that a packet matching an egress gateway policy without an egressIP on the
 * to-netdev program gets dropped.
 */
PKTGEN("tc", "tc_egressgw_ha_drop_no_egress_ip")
int egressgw_ha_drop_no_egress_ip_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_HA_DROP_NO_EGRESS_IP,
		});
}

SETUP("tc", "tc_egressgw_ha_drop_no_egress_ip")
int egressgw_ha_drop_no_egress_ip_setup(struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_NO_EGRESS_IP,
		.dir = METRIC_EGRESS,
	};

	map_delete_elem(&cilium_metrics, &key);
	ipcache_v4_add_world_entry();
	endpoint_v4_add_entry(GATEWAY_NODE_IP, 0, 0, ENDPOINT_F_HOST, 0, 0, NULL, NULL);

	create_ct_entry(ctx, client_port(TEST_HA_DROP_NO_EGRESS_IP));
	add_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP, 32, 1,
				     { GATEWAY_NODE_IP },
				     EGRESS_GATEWAY_NO_EGRESS_IP, 0);

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_egressgw_ha_drop_no_egress_ip")
int egressgw_ha_drop_no_egress_ip_check(const struct __ctx_buff *ctx)
{
	struct metrics_value *entry = NULL;
	struct metrics_key key = {};

	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = CTX_ACT_DROP,
	});
	if (ret != TEST_PASS)
		return ret;

	test_init();

	key.reason = (__u8)-DROP_NO_EGRESS_IP;
	key.dir = METRIC_EGRESS;
	entry = map_lookup_elem(&cilium_metrics, &key);
	if (!entry)
		test_fatal("metrics entry not found");

	__u64 count = 1;

	assert_metrics_count(key, count);

	del_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP, 32);
	endpoint_v4_del_entry(GATEWAY_NODE_IP);

	test_finish();
}
