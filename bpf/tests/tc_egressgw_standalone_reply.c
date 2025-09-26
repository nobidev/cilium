// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_EGRESS_GATEWAY_HA
#define ENABLE_EGRESS_GATEWAY_STANDALONE
#define ENABLE_MASQUERADE_IPV4
#define ENCAP_IFINDEX		42
#define SECONDARY_IFACE_IFINDEX	44

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

#define skb_set_tunnel_key mock_skb_set_tunnel_key
static __always_inline __maybe_unused int
mock_skb_set_tunnel_key(__maybe_unused struct __sk_buff *skb,
			const struct bpf_tunnel_key *from,
			__maybe_unused __u32 size,
			__maybe_unused __u32 flags);

#include "lib/bpf_host.h"

#include "lib/egressgw.h"
#include "lib/egressgw_ha.h"

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	if (ifindex == ENCAP_IFINDEX)
		return CTX_ACT_REDIRECT;
	if (ifindex == SECONDARY_IFACE_IFINDEX)
		return CTX_ACT_REDIRECT;

	return CTX_ACT_DROP;
}

static __always_inline __maybe_unused long
mock_fib_lookup(void *ctx __maybe_unused, struct bpf_fib_lookup *params __maybe_unused,
		int plen __maybe_unused, __u32 flags __maybe_unused)
{
	if (params && params->ipv4_src == EGRESS_IP2)
		params->ifindex = SECONDARY_IFACE_IFINDEX;

	return 0;
}

static __always_inline __maybe_unused int
mock_skb_set_tunnel_key(__maybe_unused struct __sk_buff *skb,
			const struct bpf_tunnel_key *from,
			__maybe_unused __u32 size,
			__maybe_unused __u32 flags)
{
	if (from->tunnel_id != WORLD_ID)
		return -1;
	if (from->local_ipv4 != 0)
		return -2;
	if (from->remote_ipv4 != bpf_htonl(CLIENT_NODE_IP))
		return -3;
	return 0;
}

/* Test that a packet matching an egress gateway policy on the to-netdev program
 * gets correctly SNATed with the egress IP of the policy.
 */
PKTGEN("tc", "tc_egressgw_standalone_snat")
int egressgw_standalone_snat_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_STANDALONE_SNAT,
		});
}

SETUP("tc", "tc_egressgw_standalone_snat")
int egressgw_standalone_snat_setup(struct __ctx_buff *ctx)
{
	add_egressgw_ha_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, 1,
				     { GATEWAY_NODE_IP }, EGRESS_IP, 0);

	return netdev_send_packet(ctx);
}

CHECK("tc", "tc_egressgw_standalone_snat")
int egressgw_standalone_snat_check(const struct __ctx_buff *ctx)
{
	return egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_STANDALONE_SNAT,
			.packets = 1,
			.status_code = CTX_ACT_OK
		});
}

/* Test that a packet matching an egress gateway policy on the from-netdev program
 * gets correctly revSNATed and connection tracked.
 */
PKTGEN("tc", "tc_egressgw_standalone_snat_reply")
int egressgw_standalone_snat_reply_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_STANDALONE_SNAT,
			.dir = CT_INGRESS,
		});
}

SETUP("tc", "tc_egressgw_standalone_snat_reply")
int egressgw_standalone_snat_reply_setup(struct __ctx_buff *ctx)
{
	struct egress_gw_standalone_key segw_key = { .endpoint_ip = CLIENT_IP };
	struct egress_gw_standalone_entry segw_entry = {
		.sec_identity = CLIENT_SEC_ID,
		.tunnel_endpoint = CLIENT_NODE_IP,
	};

	/* install the SEGW entry for the CLIENT_IP: */
	map_update_elem(&cilium_egress_gw_standalone_v4, &segw_key, &segw_entry, BPF_ANY);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_egressgw_standalone_snat_reply")
int egressgw_standalone_snat_reply_check(const struct __ctx_buff *ctx)
{
	return egressgw_snat_check(ctx, (struct egressgw_test_ctx) {
			.test = TEST_STANDALONE_SNAT,
			.dir = CT_INGRESS,
			.packets = 2,
			.status_code = CTX_ACT_REDIRECT,
		});
}
