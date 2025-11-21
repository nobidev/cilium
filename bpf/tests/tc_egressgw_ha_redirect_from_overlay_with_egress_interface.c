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
#define ENCAP_IFINDEX	42
#define IFACE_IFINDEX	44

#define EGRESS_IFINDEX	IFACE_IFINDEX

#define fib_lookup mock_fib_lookup
static __always_inline __maybe_unused long
mock_fib_lookup(void *ctx __maybe_unused, struct bpf_fib_lookup *params __maybe_unused,
		int plen __maybe_unused, __u32 flags __maybe_unused);

#define skb_get_tunnel_key mock_skb_get_tunnel_key
static int mock_skb_get_tunnel_key(__maybe_unused struct __sk_buff *skb,
				   struct bpf_tunnel_key *to,
				   __maybe_unused __u32 size,
				   __maybe_unused __u32 flags)
{
	to->remote_ipv4 = v4_node_one;
	/* 0xfffff is the default SECLABEL */
	to->tunnel_id = 0xfffff;
	return 0;
}

#include "lib/bpf_overlay.h"

#include "lib/egressgw.h"
#include "lib/egressgw_ha.h"
#include "lib/ipcache.h"

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	if (ifindex == IFACE_IFINDEX)
		return CTX_ACT_REDIRECT;

	return CTX_ACT_OK;
}

static __always_inline __maybe_unused long
mock_fib_lookup(void *ctx __maybe_unused, struct bpf_fib_lookup *params __maybe_unused,
		int plen __maybe_unused, __u32 flags __maybe_unused)
{
	params->ifindex = IFACE_IFINDEX;
	return 0;
}

/* Test that a packet matching an egress gateway policy on the from-overlay program
 * gets correctly redirected to the target netdev.
 */
PKTGEN("tc", "tc_egressgw_ha_redirect_from_overlay_with_egress_interface")
int egressgw_ha_redirect_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_REDIRECT,
			.redirect = true,
		});
}

SETUP("tc", "tc_egressgw_ha_redirect_from_overlay_with_egress_interface")
int egressgw_ha_redirect_setup(struct __ctx_buff *ctx)
{
	add_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, 1,
				     { GATEWAY_NODE_IP }, EGRESS_IP, EGRESS_IFINDEX);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "tc_egressgw_ha_redirect_from_overlay_with_egress_interface")
int egressgw_ha_redirect_check(const struct __ctx_buff *ctx)
{
	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = TC_ACT_REDIRECT,
	});

	del_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24);

	return ret;
}
