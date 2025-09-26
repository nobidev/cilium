// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define SECLABEL
#define SECLABEL_IPV4
#define SECLABEL_IPV6
#undef SECLABEL
#undef SECLABEL_IPV4
#undef SECLABEL_IPV6

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_EGRESS_GATEWAY_HA
#define ENABLE_EGRESS_GATEWAY_STANDALONE
#define ENABLE_MASQUERADE_IPV4
#define ENCAP_IFINDEX	42
#define IFACE_IFINDEX	44

#define SECCTX_FROM_IPCACHE 1

#define CLIENT_SEC_ID 0x012345

#define ctx_redirect mock_ctx_redirect
static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused);

#define fib_lookup mock_fib_lookup
static __always_inline __maybe_unused long
mock_fib_lookup(void *ctx __maybe_unused, struct bpf_fib_lookup *params __maybe_unused,
		int plen __maybe_unused, __u32 flags __maybe_unused);

#define skb_get_tunnel_key mock_skb_get_tunnel_key
static int mock_skb_get_tunnel_key(__maybe_unused struct __sk_buff *skb,
				   struct bpf_tunnel_key *to,
				   __maybe_unused __u32 size,
				   __maybe_unused __u32 flags);

#include "lib/bpf_overlay.h"

#include "lib/egressgw.h"
#include "lib/egressgw_ha.h"

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

static int mock_skb_get_tunnel_key(__maybe_unused struct __sk_buff *skb,
				   struct bpf_tunnel_key *to,
				   __maybe_unused __u32 size,
				   __maybe_unused __u32 flags)
{
	to->remote_ipv4 = CLIENT_NODE_IP;
	to->tunnel_id = CLIENT_SEC_ID;
	return 0;
}

/* Test that a packet matching an egress gateway policy on the from-overlay program
 * gets correctly redirected to the target netdev.
 */
PKTGEN("tc", "tc_egressgw_standalone_redirect_from_overlay")
int egressgw_standalone_redirect_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_STANDALONE_REDIRECT,
			.redirect = true,
		});
}

SETUP("tc", "tc_egressgw_standalone_redirect_from_overlay")
int egressgw_standalone_redirect_setup(struct __ctx_buff *ctx)
{
	add_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, 1,
				     { GATEWAY_NODE_IP }, EGRESS_IP, 0);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "tc_egressgw_standalone_redirect_from_overlay")
int egressgw_standalone_redirect_check(const struct __ctx_buff *ctx)
{
	struct egress_gw_standalone_key segw_key = { .endpoint_ip = CLIENT_IP };
	struct egress_gw_standalone_entry *segw_entry;

	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = TC_ACT_REDIRECT,
	});
	if (ret != TEST_PASS)
		return ret;

	test_init();

	segw_entry = map_lookup_elem(&cilium_egress_gw_standalone_v4, &segw_key);
	if (!segw_entry)
		test_fatal("no SEGW entry found");

	if (segw_entry->tunnel_endpoint != bpf_htonl(CLIENT_NODE_IP))
		test_fatal("bad tunnel endpoint in SEGW map")

	if (segw_entry->sec_identity != CLIENT_SEC_ID)
		test_fatal("bad security identity in SEGW map")

	del_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24);

	test_finish();
}
