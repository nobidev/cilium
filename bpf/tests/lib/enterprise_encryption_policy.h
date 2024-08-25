/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

static __always_inline void
add_encryption_policy_entry(__u32 src_sec_identity, __u32 dst_sec_identity, __u8 protocol, __u16 port, bool encrypt)
{
	struct encryption_policy_key key = {
		.lpm_key = { ENCRYPTION_POLICY_FULL_PREFIX, {} },
		.src_sec_identity   = src_sec_identity,
		.dst_sec_identity   = dst_sec_identity,
		.port = (__u16)port,
		.protocol = protocol
	};

	struct encryption_policy_entry val = {
		.encrypt = encrypt,
	};

	map_update_elem(&ENCRYPTION_POLICY_MAP, &key, &val, 0);
}

static __always_inline int
encryption_policy_pktgen(struct __ctx_buff *ctx, bool v4, bool tcp, bool reply)
{
	struct pktgen builder;
	void *l4 = NULL;
	void *data;

	pktgen__init(&builder, ctx);

	if (v4) {
		if (tcp)
			if (reply)
				l4 = pktgen__push_ipv4_tcp_packet(&builder,
						(__u8 *)POD2_MAC, (__u8 *)POD1_MAC,
						POD2_IPV4, POD1_IPV4,
						POD2_L4_PORT, POD1_L4_PORT);
			else
				l4 = pktgen__push_ipv4_tcp_packet(&builder,
						(__u8 *)POD1_MAC, (__u8 *)POD2_MAC,
						POD1_IPV4, POD2_IPV4,
						POD1_L4_PORT, POD2_L4_PORT);
		else
			if (reply)
				l4 = pktgen__push_ipv4_udp_packet(&builder,
						(__u8 *)POD2_MAC, (__u8 *)POD1_MAC,
						POD2_IPV4, POD1_IPV4,
						POD2_L4_PORT, POD1_L4_PORT);
			else
				l4 = pktgen__push_ipv4_udp_packet(&builder,
						(__u8 *)POD1_MAC, (__u8 *)POD2_MAC,
						POD1_IPV4, POD2_IPV4,
						POD1_L4_PORT, POD2_L4_PORT);
	} else {
		if (tcp)
			if (reply)
				l4 = pktgen__push_ipv6_tcp_packet(&builder,
						(__u8 *)POD2_MAC, (__u8 *)POD1_MAC,
						(__u8 *)POD2_IPV6, (__u8 *)POD1_IPV6,
						POD2_L4_PORT, POD1_L4_PORT);
			else
				l4 = pktgen__push_ipv6_tcp_packet(&builder,
						(__u8 *)POD1_MAC, (__u8 *)POD2_MAC,
						(__u8 *)POD1_IPV6, (__u8 *)POD2_IPV6,
						POD1_L4_PORT, POD2_L4_PORT);
		else
			if (reply)
				l4 = pktgen__push_ipv6_udp_packet(&builder,
						(__u8 *)POD2_MAC, (__u8 *)POD1_MAC,
						(__u8 *)POD2_IPV6, (__u8 *)POD1_IPV6,
						POD2_L4_PORT, POD1_L4_PORT);
			else
				l4 = pktgen__push_ipv6_udp_packet(&builder,
						(__u8 *)POD1_MAC, (__u8 *)POD2_MAC,
						(__u8 *)POD1_IPV6, (__u8 *)POD2_IPV6,
						POD1_L4_PORT, POD2_L4_PORT);
	}

	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* this had to be used instead of the pktgen__push methods since these methods
 * use layer accounting and will fail when pushing an ipv4 header past its
 * assumed layer
 */
static __always_inline void
make_inner_packet(const __u8 *buff, bool ip4) {
	struct ethhdr *eth = (struct ethhdr *)buff;

	memcpy(&eth->h_source, (__u8 *)mac_one, sizeof(mac_three));
	memcpy(&eth->h_dest, (__u8 *)mac_one, sizeof(mac_four));

	if (ip4) {
		eth->h_proto = bpf_htons(ETH_P_IP);

		struct iphdr *ipv4 = (struct iphdr *)(buff + sizeof(struct ethhdr));

		ipv4->version = 4;
		ipv4->ihl = 5;
		ipv4->protocol = 6;
		ipv4->ttl = 64;
		ipv4->frag_off = 0;
		ipv4->saddr = POD1_IPV4;
		ipv4->daddr = POD2_IPV4;

		struct tcphdr *l4 = (struct tcphdr *)(buff + sizeof(struct ethhdr)
				+ sizeof(struct iphdr));

		l4->source = POD1_L4_PORT;
		l4->dest = POD2_L4_PORT;
	} else {
		eth->h_proto = bpf_htons(ETH_P_IPV6);

		struct ipv6hdr *ipv6 = (struct ipv6hdr *)(buff + sizeof(struct ethhdr));

		ipv6->nexthdr = 6;
		memcpy((__u8 *)&ipv6->saddr, (__u8 *)POD1_IPV6, 16);
		memcpy((__u8 *)&ipv6->daddr, (__u8 *)POD2_IPV6, 16);

		struct tcphdr *l4 = (struct tcphdr *)(buff + sizeof(struct ethhdr)
				+ sizeof(struct ipv6hdr));

		l4->source = POD1_L4_PORT;
		l4->dest = POD2_L4_PORT;
	}
}

static __always_inline int
encryption_policy_encap_pktgen(struct __ctx_buff *ctx, bool inner_ip4) {
	struct pktgen builder;
	struct udphdr *l4;
	struct vxlanhdr *vx;

	__u8 __maybe_unused encap_data_v4[sizeof(struct ethhdr) + sizeof(struct iphdr)
		+ sizeof(struct tcphdr)];
	__u8 __maybe_unused encap_data_v6[sizeof(struct ethhdr) + sizeof(struct ipv6hdr)
		+ sizeof(struct tcphdr)];
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)mac_one,
					  (__u8 *)mac_two,
					  POD1_TUNNEL_IPV4,
					  POD2_TUNNEL_IPV4,
					  666,
					  bpf_htons(TUNNEL_PORT));
	if (!l4)
		return TEST_ERROR;

	l4->check = UDP_CHECK;

	vx = pktgen__push_default_vxlanhdr(&builder);
	if (!vx)
		return TEST_ERROR;

	vx->vx_vni = bpf_htonl(VXLAN_VNI << 8);

	if (inner_ip4) {
		make_inner_packet(encap_data_v4, true);
		data = pktgen__push_data(&builder, encap_data_v4, sizeof(encap_data_v4));
	} else {
		make_inner_packet(encap_data_v6, false);
		data = pktgen__push_data(&builder, encap_data_v6, sizeof(encap_data_v6));
	}
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	set_identity_mark(ctx, 0x0, MARK_MAGIC_OVERLAY);

	return 0;
}

static __always_inline int
encryption_policy_check(const struct __ctx_buff *ctx, __u32 expected_result)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == expected_result);

	test_finish();
}
