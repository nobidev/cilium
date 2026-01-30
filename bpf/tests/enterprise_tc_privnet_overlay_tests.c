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

#define privnet_tunnel_id 199
/* Enable debug output */
#define DEBUG

#include "enterprise_privnet_common.h"
#include <bpf/config/node.h>
#include <lib/enterprise_ext_eps_maps.h>

/* source mac will be set to mac_one_addr in these tests */
#undef NATIVE_DEV_MAC_BY_IFINDEX
#define NATIVE_DEV_MAC_BY_IFINDEX(_) { .addr = mac_one_addr }

static __always_inline int
mock_ext_eps_policy_can_access(struct __ctx_buff __maybe_unused *ctx,
			       struct endpoint_key __maybe_unused *key,
			       __u32 __maybe_unused sec_identity, __u16 __maybe_unused ethertype,
			       __be16 __maybe_unused dport, __u8 __maybe_unused proto,
			       int __maybe_unused l4_off, __u8 __maybe_unused *match_type,
			       int __maybe_unused dir, bool __maybe_unused is_untracked_fragment,
			       __u8 __maybe_unused *audited, __s8 __maybe_unused *ext_err,
			       __u16 __maybe_unused *proxy_port, __u32 __maybe_unused *cookie)
{
	return CTX_ACT_OK;
}

#undef ext_ep_policy_verdict
#define ext_ep_policy_verdict mock_ext_eps_policy_can_access

#undef EFFECTIVE_EP_ID

/* Include an actual datapath code */
#include "lib/bpf_overlay.h"

#include "tests/lib/enterprise_privnet.h"

/* Enable privnet */
ASSIGN_CONFIG(bool, privnet_enable, true)
ASSIGN_CONFIG(bool, privnet_bridge_enable, true)
ASSIGN_CONFIG(__u32, privnet_unknown_sec_id, 99) /* tunnel id 99 is reserved for unknown privnet flow */

PKTGEN("tc", "01_icmp_from_overlay_nat_src_dst")
int privnet_icmp_from_overlay_nat_src_dst_pktgen(struct __ctx_buff *ctx)
{
	build_privnet_packet(ctx, PODIP_ICMP_REQ);
	return 0;
}

SETUP("tc", "01_icmp_from_overlay_nat_src_dst")
int privnet_icmp_from_overlay_nat_src_dst_setup(struct __ctx_buff *ctx)
{
	privnet_v4_add_endpoint_entry(NET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, V4_NET_IP_2, V4_POD_IP_2);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "01_icmp_from_overlay_nat_src_dst")
int privnet_icmp_from_overlay_nat_src_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	/* packets are redirected to tunnel device */
	assert_status_code(ctx, TC_ACT_REDIRECT);

	ASSERT_CTX_BUF_OFF("privnet_icmp_from_overlay_nat_src_dst", "IP", ctx,
			   sizeof(__u32), NETIP_ICMP_REQ,
			   sizeof(BUF(NETIP_ICMP_REQ)));

	assert_privnet_net_ids(NET_ID, NET_ID);

	privnet_v4_del_endpoint_entry(NET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, V4_NET_IP_2, V4_POD_IP_2);

	test_finish();
}
