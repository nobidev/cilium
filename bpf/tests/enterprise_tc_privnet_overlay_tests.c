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
#define EP_IFINDEX 99
#define EP_LXC_ID 0

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

__section_entry
int mock_handle_policy(struct __ctx_buff *ctx __maybe_unused)
{
	return TC_ACT_OK;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} mock_policy_call_map __section(".maps") = {
	.values = {
		[EP_LXC_ID] = &mock_handle_policy,
	},
};

#define tail_call_dynamic mock_tail_call_dynamic
static __always_inline __maybe_unused void
mock_tail_call_dynamic(struct __ctx_buff *ctx __maybe_unused,
		       const void *map __maybe_unused, __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

/* Include an actual datapath code */
#include "lib/bpf_overlay.h"

#include "tests/lib/endpoint.h"
#include "tests/lib/enterprise_privnet.h"
#include "tests/lib/network_device.h"

/* Enable privnet */
ASSIGN_CONFIG(bool, privnet_enable, true)
ASSIGN_CONFIG(bool, privnet_local_access_enable, false)
ASSIGN_CONFIG(bool, privnet_bridge_enable, true)
ASSIGN_CONFIG(__u32, privnet_unknown_sec_id, 99) /* tunnel id 99 is reserved for unknown privnet flow */

PKTGEN("tc", "01_icmp_from_overlay_nat_src_dst")
int privnet_icmp_from_overlay_nat_src_dst_pktgen(struct __ctx_buff *ctx)
{
	BUF_DECL(PODIP_ICMP_REQ, privnet_pod_ip_icmp_req);
	build_privnet_packet(ctx, PODIP_ICMP_REQ);
	return 0;
}

SETUP("tc", "01_icmp_from_overlay_nat_src_dst")
int privnet_icmp_from_overlay_nat_src_dst_setup(struct __ctx_buff *ctx)
{
	const __u8 mac[] = mac_one_addr;
	cilium_device_add_entry(ENCAP_IFINDEX, mac, 0);

	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_add_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "01_icmp_from_overlay_nat_src_dst")
int privnet_icmp_from_overlay_nat_src_dst_check(struct __ctx_buff *ctx)
{
	test_init();

	/* packets are redirected to tunnel device */
	assert_status_code(ctx, TC_ACT_REDIRECT);

	BUF_DECL(NETIP_ICMP_REQ, privnet_net_ip_icmp_req);
	ASSERT_CTX_BUF_OFF("privnet_icmp_from_overlay_nat_src_dst", "IP", ctx,
			   sizeof(__u32), NETIP_ICMP_REQ,
			   sizeof(BUF(NETIP_ICMP_REQ)));

	assert_privnet_net_ids(NET_ID, NET_ID);

	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_1, V4_POD_IP_1);
	privnet_v4_del_endpoint_entry(NET_ID, SUBNET_ID, V4_NET_IP_2, V4_POD_IP_2);

	test_finish();
}

PKTGEN("tc", "02_icmp_from_overlay_to_local_endpoint")
int privnet_icmp_from_overlay_to_local_endpoint_pktgen(struct __ctx_buff *ctx)
{
	BUF_DECL(EP_V4_ICMP_REQ, privnet_pod_ip_icmp_req_to_endpoint);
	build_privnet_packet(ctx, EP_V4_ICMP_REQ);
	return 0;
}

SETUP("tc", "02_icmp_from_overlay_to_local_endpoint")
int privnet_icmp_from_overlay_to_local_endpoint_setup(struct __ctx_buff *ctx)
{
	/* Create an endpoint map entry to force local delivery */
	endpoint_v4_add_entry(V4_EP_IP, EP_IFINDEX, EP_LXC_ID, 0, 0, 0,
			      (__u8 *)mac_three, (__u8 *)mac_four);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "02_icmp_from_overlay_to_local_endpoint")
int privnet_icmp_from_overlay_to_local_endpoint_check(struct __ctx_buff *ctx)
{
	test_init();

	endpoint_v4_del_entry(V4_EP_IP);
	assert_status_code(ctx, CTX_ACT_OK);

	test_finish();
}

PKTGEN("tc", "03_icmp_from_overlay_to_local_endpoint_v6")
int privnet_icmp_from_overlay_to_local_endpoint_v6_pktgen(struct __ctx_buff *ctx)
{
	BUF_DECL(EP_V6_ICMP_REQ, privnet_pod_ipv6_icmp_req_to_endpoint);
	build_privnet_packet(ctx, EP_V6_ICMP_REQ);
	return 0;
}

SETUP("tc", "03_icmp_from_overlay_to_local_endpoint_v6")
int privnet_icmp_from_overlay_to_local_endpoint_v6_setup(struct __ctx_buff *ctx)
{
	/* Create an endpoint map entry to force local delivery */
	endpoint_v6_add_entry((const union v6addr *)v6_ep_ip, EP_IFINDEX, EP_LXC_ID, 0, 0,
			      (__u8 *)mac_three, (__u8 *)mac_four);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "03_icmp_from_overlay_to_local_endpoint_v6")
int privnet_icmp_from_overlay_to_local_endpoint_v6_check(struct __ctx_buff *ctx)
{
	test_init();

	/* endpoint_v6_del_entry is not defined upstream. Let's keep things
	 * simple and open-code it here.
	 */
	struct endpoint_key key = {
		.ip6 = *((const union v6addr *)v6_ep_ip),
		.family = ENDPOINT_KEY_IPV6,
	};
	map_delete_elem(&cilium_lxc, &key);

	assert_status_code(ctx, CTX_ACT_OK);

	test_finish();
}
