/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
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

#include "lib/bpf_host.h"

#include "lib/ipcache.h"
#include "lib/enterprise_encryption_policy.h"

ASSIGN_CONFIG(__u32, wg_ifindex, 42)
ASSIGN_CONFIG(__u16, wg_port, 51871)

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

	/* insert encryption policy: encrypt flips based on fallback mode */
	add_encryption_policy_entry(POD1_SEC_IDENTITY, POD2_SEC_IDENTITY, IPPROTO_TCP,
				    POD2_L4_PORT,
				    !CONFIG(encryption_policy_fallback_encrypt));

	return netdev_send_packet(ctx);
}

CHECK("tc", "01_tc_encryption_policy_native_v4_tcp_match")
int encryption_policy_native_v4_tcp_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx,
		CONFIG(encryption_policy_fallback_encrypt) ? CTX_ACT_OK : CTX_ACT_REDIRECT);
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
	return netdev_send_packet(ctx);
}

CHECK("tc", "02_tc_encryption_policy_native_v4_tcp_reply_match")
int encryption_policy_native_v4_tcp_reply_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx,
		CONFIG(encryption_policy_fallback_encrypt) ? CTX_ACT_OK : CTX_ACT_REDIRECT);
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
	/* insert encryption policy with opposite encrypt value */
	add_encryption_policy_entry(POD1_SEC_IDENTITY, POD2_SEC_IDENTITY, IPPROTO_TCP,
				    POD2_L4_PORT,
				    CONFIG(encryption_policy_fallback_encrypt));

	return netdev_send_packet(ctx);
}

CHECK("tc", "03_tc_encryption_policy_native_v4_tcp_no_match")
int encryption_policy_native_v4_tcp_no_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx,
		CONFIG(encryption_policy_fallback_encrypt) ? CTX_ACT_REDIRECT : CTX_ACT_OK);
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

	/* insert encryption policy: encrypt flips based on fallback mode */
	add_encryption_policy_entry(POD1_SEC_IDENTITY, POD2_SEC_IDENTITY, IPPROTO_TCP,
				    POD2_L4_PORT,
				    !CONFIG(encryption_policy_fallback_encrypt));

	return netdev_send_packet(ctx);
}

CHECK("tc", "04_tc_encryption_policy_native_v6_tcp_match")
int encryption_policy_native_v6_tcp_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx,
		CONFIG(encryption_policy_fallback_encrypt) ? CTX_ACT_OK : CTX_ACT_REDIRECT);
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
	return netdev_send_packet(ctx);
}

CHECK("tc", "05_tc_encryption_policy_native_v6_tcp_reply_match")
int encryption_policy_native_v6_tcp_reply_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx,
		CONFIG(encryption_policy_fallback_encrypt) ? CTX_ACT_OK : CTX_ACT_REDIRECT);
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
	/* insert encryption policy with opposite encrypt value */
	add_encryption_policy_entry(POD1_SEC_IDENTITY, POD2_SEC_IDENTITY, IPPROTO_TCP,
				    POD2_L4_PORT,
				    CONFIG(encryption_policy_fallback_encrypt));

	return netdev_send_packet(ctx);
}

CHECK("tc", "06_tc_encryption_policy_native_v6_tcp_no_match")
int encryption_policy_native_v6_tcp_no_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx,
		CONFIG(encryption_policy_fallback_encrypt) ? CTX_ACT_REDIRECT : CTX_ACT_OK);
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
	/* insert encryption policy: encrypt flips based on fallback mode */
	add_encryption_policy_entry(POD1_SEC_IDENTITY, POD2_SEC_IDENTITY, IPPROTO_TCP,
				    POD2_L4_PORT,
				    !CONFIG(encryption_policy_fallback_encrypt));

	return netdev_send_packet(ctx);
}

CHECK("tc", "07_tc_encryption_policy_vxlan_v4_tcp_match")
int encryption_policy_vxlan_v4_tcp_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx,
		CONFIG(encryption_policy_fallback_encrypt) ? CTX_ACT_OK : CTX_ACT_REDIRECT);
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
	/* insert encryption policy with opposite encrypt value */
	add_encryption_policy_entry(POD1_SEC_IDENTITY, POD2_SEC_IDENTITY, IPPROTO_TCP,
				    POD2_L4_PORT,
				    CONFIG(encryption_policy_fallback_encrypt));

	return netdev_send_packet(ctx);
}

CHECK("tc", "08_tc_encryption_policy_vxlan_v4_tcp_no_match")
int encryption_policy_vxlan_v4_tcp_no_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx,
		CONFIG(encryption_policy_fallback_encrypt) ? CTX_ACT_REDIRECT : CTX_ACT_OK);
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
	/* insert encryption policy: encrypt flips based on fallback mode */
	add_encryption_policy_entry(POD1_SEC_IDENTITY, POD2_SEC_IDENTITY, IPPROTO_TCP,
				    POD2_L4_PORT,
				    !CONFIG(encryption_policy_fallback_encrypt));

	return netdev_send_packet(ctx);
}

CHECK("tc", "09_tc_encryption_policy_vxlan_v6_tcp_match")
int encryption_policy_vxlan_v6_tcp_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx,
		CONFIG(encryption_policy_fallback_encrypt) ? CTX_ACT_OK : CTX_ACT_REDIRECT);
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
	/* insert encryption policy with opposite encrypt value */
	add_encryption_policy_entry(POD1_SEC_IDENTITY, POD2_SEC_IDENTITY, IPPROTO_TCP,
				    POD2_L4_PORT,
				    CONFIG(encryption_policy_fallback_encrypt));

	return netdev_send_packet(ctx);
}

CHECK("tc", "10_tc_encryption_policy_vxlan_v6_tcp_no_match")
int encryption_policy_vxlan_v6_tcp_no_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx,
		CONFIG(encryption_policy_fallback_encrypt) ? CTX_ACT_REDIRECT : CTX_ACT_OK);
}

/* Test that a native ipv4 ICMP packet matching an encryption policy
 * on the to-netdev program gets correctly directed to the wireguard device.
 */
PKTGEN("tc", "11_tc_encryption_policy_native_v4_icmp_match")
int encryption_policy_native_v4_icmp_match_pktgen(struct __ctx_buff *ctx)
{
	return encryption_policy_icmp_pktgen(ctx);
}

SETUP("tc", "11_tc_encryption_policy_native_v4_icmp_match")
int encryption_policy_native_v4_icmp_match_setup(struct __ctx_buff *ctx)
{
	/* ICMP has no ports, so the policy entry uses port=0 and a shorter prefix */
	add_encryption_policy_entry_with_prefix(80, POD1_SEC_IDENTITY, POD2_SEC_IDENTITY,
						IPPROTO_ICMP, 0,
						!CONFIG(encryption_policy_fallback_encrypt));

	return netdev_send_packet(ctx);
}

CHECK("tc", "11_tc_encryption_policy_native_v4_icmp_match")
int encryption_policy_native_v4_icmp_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx,
		CONFIG(encryption_policy_fallback_encrypt) ? CTX_ACT_OK : CTX_ACT_REDIRECT);
}

/* Test that a native ipv4 SCTP packet matching an encryption policy
 * on the to-netdev program gets correctly directed to the wireguard device.
 */
PKTGEN("tc", "12_tc_encryption_policy_native_v4_sctp_match")
int encryption_policy_native_v4_sctp_match_pktgen(struct __ctx_buff *ctx)
{
	return encryption_policy_sctp_pktgen(ctx);
}

SETUP("tc", "12_tc_encryption_policy_native_v4_sctp_match")
int encryption_policy_native_v4_sctp_match_setup(struct __ctx_buff *ctx)
{
	/* insert encryption policy: encrypt flips based on fallback mode */
	add_encryption_policy_entry(POD1_SEC_IDENTITY, POD2_SEC_IDENTITY, IPPROTO_SCTP,
				    POD2_L4_PORT,
				    !CONFIG(encryption_policy_fallback_encrypt));

	return netdev_send_packet(ctx);
}

CHECK("tc", "12_tc_encryption_policy_native_v4_sctp_match")
int encryption_policy_native_v4_sctp_match_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx,
		CONFIG(encryption_policy_fallback_encrypt) ? CTX_ACT_OK : CTX_ACT_REDIRECT);
}

/* Test that a UDP packet is handled according to fallback behavior
 * when no explicit map entry exists.
 */
PKTGEN("tc", "13_tc_encryption_policy_fallback_no_entry")
int encryption_policy_fallback_no_entry_pktgen(struct __ctx_buff *ctx)
{
	return encryption_policy_pktgen(ctx, true, false, false);
}

SETUP("tc", "13_tc_encryption_policy_fallback_no_entry")
int encryption_policy_fallback_no_entry_setup(struct __ctx_buff *ctx)
{
	/* no encryption policy map entries — fallback behavior applies */
	return netdev_send_packet(ctx);
}

CHECK("tc", "13_tc_encryption_policy_fallback_no_entry")
int encryption_policy_fallback_no_entry_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx,
		CONFIG(encryption_policy_fallback_encrypt) ? CTX_ACT_REDIRECT : CTX_ACT_OK);
}

/* Test that the bidirectional lookup correctly picks the more specific entry.
 * A reply packet has:
 *   forward  (POD2->POD1): matches prefix=64 encrypt=true  (wildcard port)
 *   reverse  (POD1->POD2): matches prefix=96 encrypt=false (specific opt-out)
 * Since rev prefix (96) > fwd prefix (64), the opt-out wins -> not encrypted.
 */
PKTGEN("tc", "14_tc_encryption_policy_bidir_optout_wins")
int encryption_policy_bidir_optout_wins_pktgen(struct __ctx_buff *ctx)
{
	return encryption_policy_pktgen(ctx, true, false, true);
}

SETUP("tc", "14_tc_encryption_policy_bidir_optout_wins")
int encryption_policy_bidir_optout_wins_setup(struct __ctx_buff *ctx)
{
	/* insert specific opt-out entry (encrypt=false) at prefix=96 for POD1->POD2 */
	add_encryption_policy_entry(POD1_SEC_IDENTITY, POD2_SEC_IDENTITY, IPPROTO_UDP,
				    POD2_L4_PORT, false);

	/* Add an encrypt entry at prefix=64 (identity-pair only, wildcard port/proto)
	 * for the forward direction of the reply packet (POD2->POD1).
	 */
	add_encryption_policy_entry_with_prefix(64, POD2_SEC_IDENTITY,
						POD1_SEC_IDENTITY, 0, 0, true);

	return netdev_send_packet(ctx);
}

CHECK("tc", "14_tc_encryption_policy_bidir_optout_wins")
int encryption_policy_bidir_optout_wins_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx, CTX_ACT_OK);
}

/* Test that when both forward and reverse lookups match at the same prefix
 * length with conflicting encrypt values, encrypt wins (security-first).
 *
 * Packet POD1->POD2 (forward, not reply):
 *   forward  (POD1->POD2): prefix=96 encrypt=false (kept from test 14)
 *   reverse  (POD2->POD1): prefix=96 encrypt=true  (added here)
 * Equal prefix -> fwd->encrypt || rev->encrypt = true -> encrypted.
 */
PKTGEN("tc", "15_tc_encryption_policy_bidir_equal_prefix_encrypt_wins")
int encryption_policy_bidir_equal_prefix_encrypt_wins_pktgen(struct __ctx_buff *ctx)
{
	return encryption_policy_pktgen(ctx, true, false, false);
}

SETUP("tc", "15_tc_encryption_policy_bidir_equal_prefix_encrypt_wins")
int encryption_policy_bidir_equal_prefix_encrypt_wins_setup(struct __ctx_buff *ctx)
{
	/* clean up the prefix=64 wildcard entry from test 14 */
	del_encryption_policy_entry_with_prefix(64, POD2_SEC_IDENTITY,
						POD1_SEC_IDENTITY, 0, 0);

	/* The prefix=96 encrypt=false entry (POD1->POD2, UDP) from test 14
	 * is still in the map. Add a conflicting encrypt=true entry at the
	 * same prefix for the reverse direction (POD2->POD1, UDP).
	 */
	add_encryption_policy_entry(POD2_SEC_IDENTITY, POD1_SEC_IDENTITY, IPPROTO_UDP,
				    POD1_L4_PORT, true);

	return netdev_send_packet(ctx);
}

CHECK("tc", "15_tc_encryption_policy_bidir_equal_prefix_encrypt_wins")
int encryption_policy_bidir_equal_prefix_encrypt_wins_check(const struct __ctx_buff *ctx)
{
	return encryption_policy_check(ctx, CTX_ACT_REDIRECT);
}
