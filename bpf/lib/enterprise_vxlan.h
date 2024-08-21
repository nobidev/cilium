/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include "lib/csum.h"

/*
 * Points 'inner' to the inner IPv6 header of a IPv4 VXLan excapsulated
 * packet.
 *
 * The caller should be sure the VXLan packet is encapsulating IPv6 traffic
 * before calling this method.
 *
 * Returns 'true' if 'inner' now points to a bounds-checked inner IPv6 header.
 * Returns 'false' if an error occurred.
 */
static __always_inline bool
vxlan_get_inner_ipv6(const void *data, const void *data_end, __u32 l4_off,
		     struct ipv6hdr **inner) {
	if (data + l4_off + sizeof(struct udphdr)
	    + sizeof(struct vxlanhdr) + sizeof(struct ethhdr) +
	    sizeof(struct ipv6hdr) > data_end)
		return false;

	*inner = (struct ipv6hdr *)(data + l4_off  + sizeof(struct udphdr) +
		  sizeof(struct vxlanhdr) + sizeof(struct ethhdr));

	return true;
}

/*
 * Returns the protocol number of the encapsulated packet.
 *
 * The caller must ensure the skb associated with these data buffers are infact
 * a vxlan encapsulated packet before invoking this function.
 *
 * Returns 'ethhdr->h_proto' if the bounds-check to inner ethernet header
 * was successful.
 * Returns -1 otherwise.
 */
static __always_inline __be16
vxlan_get_inner_proto(const void *data, const void *data_end, __u32 l4_off) {
	struct ethhdr *eth = NULL;
	int inner_l2_off = l4_off + sizeof(struct udphdr) + sizeof(struct vxlanhdr);

	if (data + inner_l2_off + sizeof(struct ethhdr) > data_end)
		return -1;

	eth = (struct ethhdr *)(data + inner_l2_off);

	return eth->h_proto;
}
