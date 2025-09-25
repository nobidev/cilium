// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/*
 * Test Configuration Settings
 */
#define POD1_MAC mac_one
#define POD1_IPV4 v4_pod_one
#define POD1_IPV6 v6_pod_one
#define POD1_L4_PORT tcp_src_one
#define POD1_TUNNEL_IPV4 v4_node_one
#define POD1_SEC_IDENTITY 1000

#define POD2_MAC mac_two
#define POD2_IPV4 v4_pod_two
#define POD2_IPV6 v6_pod_two
#define POD2_L4_PORT tcp_dst_one
#define POD2_TUNNEL_IPV4 v4_node_two
#define POD2_SEC_IDENTITY 2000

/*
 * Datapath configuration settings (wireguard, encryption policy, vxlan tunneling)
 */
#define ENABLE_IPV4
#define ENABLE_IPV6

#define ENABLE_WIREGUARD

#define ENABLE_ENCRYPTION_POLICY

#define TUNNEL_PROTOCOL		TUNNEL_PROTOCOL_VXLAN
#define ENCAP_IFINDEX		42
#define TUNNEL_PORT 8472
#define TUNNEL_PORT_BAD 0
#define VXLAN_VNI 0xDEADBE
#define VXLAN_VNI_NEW 0xCAFEBE
#define UDP_CHECK 0xDEAD

#include "bpf_host.c"

#include "lib/ipcache.h"
#include "lib/enterprise_encryption_policy.h"

#define TO_NETDEV 0

ASSIGN_CONFIG(__u32, wg_ifindex, 42)
ASSIGN_CONFIG(__u16, wg_port, 51871)

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[TO_NETDEV] = &cil_to_netdev,
	},
};

int mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused, int ifindex, __u32 flags)
{
	int wg_ifindex = CONFIG(wg_ifindex);
	if (ifindex != wg_ifindex)
		return -1;
	if (flags != 0)
		return -2;
	return CTX_ACT_REDIRECT;
}

/* Test that a native ipv4 packet matching an encryption policy
 * on the to-netdev program gets correctly directed to the wireguard device.
 */
PKTGEN("tc", "01_tc_encryption_policy_native_v4_tcp_match")
int encryption_policy_native_v4_tcp_match_pktgen(struct __ctx_buff *ctx)
{
	return encryption_policy_pktgen(ctx, true, true, false);
}

SETUP("tc", "01_tc_encryption_policy_native_v4_tcp_match")
int encryption_policy_native_v4_tcp_match_setup(struct __ctx_buff *ctx)
{
	/* install ipcache entries for both endpoints */
	ipcache_v4_add_entry(POD1_IPV4, 0, POD1_SEC_IDENTITY, POD1_TUNNEL_IPV4, 255);
	ipcache_v4_add_entry(POD2_IPV4, 0, POD2_SEC_IDENTITY, POD2_TUNNEL_IPV4, 255);

	/* insert encryption policy */
	add_encryption_policy_entry(POD1_SEC_IDENTITY, POD2_SEC_IDENTITY, IPPROTO_TCP,
				    POD2_L4_PORT, true);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "01_tc_encryption_policy_native_v4_tcp_match")
int encryption_policy_native_v4_tcp_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx, CTX_ACT_REDIRECT);
}

/* Test that a native ipv4 reply packet matching an encryption policy
 * on the to-netdev program gets correctly directed to the wireguard device.
 */
PKTGEN("tc", "02_tc_encryption_policy_native_v4_tcp_reply_match")
int encryption_policy_native_v4_tcp_reply_match_pktgen(struct __ctx_buff *ctx)
{
	return encryption_policy_pktgen(ctx, true, true, true);
}

SETUP("tc", "02_tc_encryption_policy_native_v4_tcp_reply_match")
int encryption_policy_native_v4_tcp_reply_match_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "02_tc_encryption_policy_native_v4_tcp_reply_match")
int encryption_policy_native_v4_tcp_reply_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx, CTX_ACT_REDIRECT);
}

/* Test that a native ipv4 packet not matching an encryption policy
 * on the to-netdev program will not be directed to the wireguard device.
 */
PKTGEN("tc", "03_tc_encryption_policy_native_v4_tcp_no_match")
int encryption_policy_native_v4_tcp_no_match_pktgen(struct __ctx_buff *ctx)
{
	return encryption_policy_pktgen(ctx, true, true, false);
}

SETUP("tc", "03_tc_encryption_policy_native_v4_tcp_no_match")
int encryption_policy_native_v4_tcp_no_match_setup(struct __ctx_buff *ctx)
{
	/* insert encryption policy */
	add_encryption_policy_entry(POD1_SEC_IDENTITY, POD2_SEC_IDENTITY, IPPROTO_TCP,
				    POD2_L4_PORT, false);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "03_tc_encryption_policy_native_v4_tcp_no_match")
int encryption_policy_native_v4_tcp_no_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx, CTX_ACT_OK);
}

/* Test that a native ipv6 packet matching an encryption policy
 * on the to-netdev program gets correctly directed to the wireguard device.
 */
PKTGEN("tc", "04_tc_encryption_policy_native_v6_tcp_match")
int encryption_policy_native_v6_tcp_match_pktgen(struct __ctx_buff *ctx)
{
	return encryption_policy_pktgen(ctx, false, true, false);
}

SETUP("tc", "04_tc_encryption_policy_native_v6_tcp_match")
int encryption_policy_native_v6_tcp_match_setup(struct __ctx_buff *ctx)
{
	/* install ipcache entries for both endpoints */
	ipcache_v6_add_entry((union v6addr *)POD1_IPV6, 0, POD1_SEC_IDENTITY,
			     POD1_TUNNEL_IPV4, 255);
	ipcache_v6_add_entry((union v6addr *)POD2_IPV6, 0, POD2_SEC_IDENTITY,
			     POD2_TUNNEL_IPV4, 255);

	/* insert encryption policy */
	add_encryption_policy_entry(POD1_SEC_IDENTITY, POD2_SEC_IDENTITY, IPPROTO_TCP,
				    POD2_L4_PORT, true);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "04_tc_encryption_policy_native_v6_tcp_match")
int encryption_policy_native_v6_tcp_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx, CTX_ACT_REDIRECT);
}

/* Test that a native ipv6 reply packet matching an encryption policy
 * on the to-netdev program gets correctly directed to the wireguard device.
 */
PKTGEN("tc", "05_tc_encryption_policy_native_v6_tcp_reply_match")
int encryption_policy_native_v6_tcp_reply_match_pktgen(struct __ctx_buff *ctx)
{
	return encryption_policy_pktgen(ctx, false, true, true);
}

SETUP("tc", "05_tc_encryption_policy_native_v6_tcp_reply_match")
int encryption_policy_native_v6_tcp_reply_match_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "05_tc_encryption_policy_native_v6_tcp_reply_match")
int encryption_policy_native_v6_tcp_reply_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx, CTX_ACT_REDIRECT);
}

/* Test that a native ipv6 packet not matching an encryption policy
 * on the to-netdev program will not be directed to the wireguard device.
 */
PKTGEN("tc", "06_tc_encryption_policy_native_v6_tcp_no_match")
int encryption_policy_native_v6_tcp_no_match_pktgen(struct __ctx_buff *ctx)
{
	return encryption_policy_pktgen(ctx, false, true, false);
}

SETUP("tc", "06_tc_encryption_policy_native_v6_tcp_no_match")
int encryption_policy_native_v6_tcp_no_match_setup(struct __ctx_buff *ctx)
{
	/* insert encryption policy */
	add_encryption_policy_entry(POD1_SEC_IDENTITY, POD2_SEC_IDENTITY, IPPROTO_TCP,
				    POD2_L4_PORT, false);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "06_tc_encryption_policy_native_v6_tcp_no_match")
int encryption_policy_native_v6_tcp_no_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx, CTX_ACT_OK);
}

/* Test that a vxlan encapsulated ipv4 packet matching an encryption policy
 * on the to-netdev program gets correctly directed to the wireguard device.
 */
PKTGEN("tc", "07_tc_encryption_policy_vxlan_v4_tcp_match")
int encryption_policy_vxlan_v4_tcp_match_pktgen(struct __ctx_buff *ctx)
{
	return encryption_policy_encap_pktgen(ctx, true);
}

SETUP("tc", "07_tc_encryption_policy_vxlan_v4_tcp_match")
int encryption_policy_vxlan_v4_tcp_match_setup(struct __ctx_buff *ctx)
{
	/* insert encryption policy */
	add_encryption_policy_entry(POD1_SEC_IDENTITY, POD2_SEC_IDENTITY, IPPROTO_TCP,
				    POD2_L4_PORT, true);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "07_tc_encryption_policy_vxlan_v4_tcp_match")
int encryption_policy_vxlan_v4_tcp_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx, CTX_ACT_REDIRECT);
}

/* Test that a vxlan encapsulated ipv4 packet not matching an encryption policy
 * on the to-netdev program will not be directed to the wireguard device.
 */
PKTGEN("tc", "08_tc_encryption_policy_vxlan_v4_tcp_no_match")
int encryption_policy_vxlan_v4_tcp_no_match_pktgen(struct __ctx_buff *ctx)
{
	return encryption_policy_encap_pktgen(ctx, true);
}

SETUP("tc", "08_tc_encryption_policy_vxlan_v4_tcp_no_match")
int encryption_policy_vxlan_v4_tcp_no_match_setup(struct __ctx_buff *ctx)
{
	/* insert encryption policy */
	add_encryption_policy_entry(POD1_SEC_IDENTITY, POD2_SEC_IDENTITY, IPPROTO_TCP,
				    POD2_L4_PORT, false);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "08_tc_encryption_policy_vxlan_v4_tcp_no_match")
int encryption_policy_vxlan_v4_tcp_no_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx, CTX_ACT_OK);
}

/* Test that a vxlan encapsulated ipv6 packet matching an encryption policy
 * on the to-netdev program gets correctly directed to the wireguard device.
 */
PKTGEN("tc", "09_tc_encryption_policy_vxlan_v6_tcp_match")
int encryption_policy_vxlan_v6_tcp_match_pktgen(struct __ctx_buff *ctx)
{
	return encryption_policy_encap_pktgen(ctx, false);
}

SETUP("tc", "09_tc_encryption_policy_vxlan_v6_tcp_match")
int encryption_policy_vxlan_v6_tcp_match_setup(struct __ctx_buff *ctx)
{
	/* insert encryption policy */
	add_encryption_policy_entry(POD1_SEC_IDENTITY, POD2_SEC_IDENTITY, IPPROTO_TCP,
				    POD2_L4_PORT, true);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "09_tc_encryption_policy_vxlan_v6_tcp_match")
int encryption_policy_vxlan_v6_tcp_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx, CTX_ACT_REDIRECT);
}

/* Test that a vxlan encapsulated ipv6 packet not matching an encryption policy
 * on the to-netdev program will not be directed to the wireguard device.
 */
PKTGEN("tc", "10_tc_encryption_policy_vxlan_v6_tcp_no_match")
int encryption_policy_vxlan_v6_tcp_no_match_pktgen(struct __ctx_buff *ctx)
{
	return encryption_policy_encap_pktgen(ctx, true);
}

SETUP("tc", "10_tc_encryption_policy_vxlan_v6_tcp_no_match")
int encryption_policy_vxlan_v6_tcp_no_match_setup(struct __ctx_buff *ctx)
{
	/* insert encryption policy */
	add_encryption_policy_entry(POD1_SEC_IDENTITY, POD2_SEC_IDENTITY, IPPROTO_TCP,
				    POD2_L4_PORT, false);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "10_tc_encryption_policy_vxlan_v6_tcp_no_match")
int encryption_policy_vxlan_v6_tcp_no_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx, CTX_ACT_OK);
}
