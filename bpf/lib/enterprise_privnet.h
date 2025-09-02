/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/arp.h"
#include "enterprise_ext_eps_policy.h"

/*
 * Privnet datapath for communication between kubernetes cluster and Isovalent Network Bridge.
 *
 *  ┌─────────────────────────────────────────────────────────────────────┐             ┌───────────────────────────────────────────────┐
 *  │                                                                     │             │                                               │
 *  │                       K8s cluster                                   │             │                 Bridge                        │
 *  │                                                                     │             │                                               │
 *  │ ┌─────────────────────┐       ┌────────────────────────────────────┐│             │ ┌──────────────────┐  ┌────────────────┐      │┌──────────────────┐
 *  │ │ Pod1                │       │ BPF LXC                            ││             │ │ BPF overlay      │  │ BPF netdev     │      ││ External VM      │
 *  │ │                     │       │                                    ││             │ │                  │  │                │      ││                  │
 *  │ │ mac:  pm1           │       │                                    ││             │ │                  │ ││                │net a ││ mac: ext_m3      │
 *  │ │ ip:   ip4_1 ip6_1   │   │   │                   │                ││             │ │                  │ ││                │eth_a ││ ip:  ip4_3 ip6_3 │
 *  │ │ routes:             │   │   │                   │                ││             │ │                  │ ││                │mac_a ││                  │
 *  │ │ default via LL addr │   │   │ cil_from_con      │ cil_lxc_policy ││             │ │cil_from_overlay  │ ││ do_netdev      │      ││                  │
 *  │ └─────────────────────┘   │   └───────────────────┼────────────────┘│             │ └──────────────────┘ │└────────────────┘      │└──────────────────┘
 *  │                           │                       │                 │             │                      │                        │
 *──┼───────────────────────────┼───────────────────────┼─────────────────┼─────────────┼──────────────────────┼────────────────────────┼──────────────────────────
 *  │ 1. ARP Handling           │                       │                 │             │                      │                        │
 *  │ arp:                      │                       │                 │             │                      │                        │
 *  │     who is 169.254.0.1    │                       │                 │             │                      │                        │
 *  │ ns:                       │                       │                 │             │                      │                        │
 *  │     who is ff80::100      │      ┌─────────┐      │                 │             │                      │                        │
 *  │                           │      │ Blind   │      │                 │             │                      │                        │
 *  │                    ───────┼─────►│ Response│      │                 │             │                      │                        │      arp
 *  │                           │      │         │      │                 │             │                      │                        │       who is ip4_1
 *  │                           │      └────┬────┘      │                 │             │                      │                        │      ns
 *  │                           │           │           │                 │             │                      │  ┌──────────┐          │       who is ip6_1
 *  │                           │           │           │                 │             │                      │  │privnet   │◄─────────┼─────
 *  │     arp reply             │           │           │                 │             │                      │  │fib       │          │
 *  │     na             ◄──────┼───────────┘           │                 │             │                      │  │lookup    │          │
 *  │        lxc mac            │                       │                 │             │                      │  └────┬─────┘          │
 *  │                           │                       │                 │             │                      │       │                │
 *  │                           │                       │                 │             │                      │       │                │
 *  │                           │                       │                 │             │                      │       │   Proxy response
 *  │                           │                       │                 │             │                      │       └────────────────┬─────►
 *  │                           │                       │                 │             │                      │               mac_a    │
 *──┼───────────────────────────┼───────────────────────┼─────────────────┼─────────────┼──────────────────────┼────────────────────────┼──────────────────────────
 *  │ 2. From Pod to External EP│        cil_from_con   │ cil_lxc_policy  │             │   cil_from_overlay   │   do_netdev            │
 *  │                           │                       │                 │             │                      │                        │
 *  │                           │     ┌───────────────┐ │                 │             │                      │                        │
 *  │                           │     │privnet egress │ │                 │             │                      │                        │
 *  │                           │     │               │ │                 │             │                      │                        │
 *  │      sm: pm1              │     │privnet-fib    │ │                 │             │                      │                        │
 *  │      dm: lxcm     ────────┼────►│snat/dnat      │ │                 │             │                      │                        │
 *  │      sip: ip4_1           │     │enforce-seg    │ │                 │             │                      │                        │
 *  │      dip: ip4_3           │     └─────┬─────────┘ │                 │             │                      │                        │
 *  │                           │           │           │                 │             │                      │                        │
 *  │                           │           ▼           │                 │             │                      │                        │
 *  │                           │      sm: pm1          │                 │             │   ┌───────────────┐  │                        │
 *  │                           │      dm: lxcm         │                 │             │   │External EP    │  │                        │
 *  │                           │      sip: ip4_pip1 ───┼─────────[─Encapsulated─]──────┼──►│Ingress Policy │  │                        │
 *  │                           │      dip: ip4_pip3    │                 │             │   │               │  │                        │
 *  │                           │                       │                 │             │   └───────┬───────┘  │                        │
 *  │                           │                       │                 │             │           │          │                        │
 *  │                           │                       │                 │             │           ▼          │                        │
 *  │                           │                       │                 │             │   ┌───────────────┐  │                        │
 *  │                           │                       │                 │             │   │privnet ingress│  │                        │
 *  │                           │                       │                 │             │   │               │  │                        │
 *  │                           │                       │                 │             │   │privnet-pip    │  │                        │
 *  │                           │                       │                 │             │   │rev snat/dnat  │  │                        │
 *  │                           │                       │                 │             │   │enforce seg    │  │                        │
 *  │                           │                       │                 │             │   └───────┬───────┘  │                        │
 *  │                           │                       │                 │             │           │          │                        │
 *  │                           │                       │                 │             │           ▼          │                        │
 *  │                           │                       │                 │             │        sm: mac_a     │                        │
 *  │                           │                       │                 │             │        dm: ext_m3    │                        │
 *  │                           │                       │                 │             │        sip: ip4_1  ──┼────────────────────────┼─────►
 *  │                           │                       │                 │             │        dip: ip4_3    │                        │
 *──┼───────────────────────────┼───────────────────────┼─────────────────┼─────────────┼──────────────────────┼────────────────────────┼──────────────────────────
 *  │ 3. From External EP to Pod│       cil_from_con    │  cil_lxc_policy │             │  cil_from_overlay    │   do_netdev            │
 *  │                           │                       │                 │             │                      │                        │
 *  │                           │                       │                 │             │                      │  ┌───────────────┐     │
 *  │                           │                       │                 │             │                      │  │privnet egress │     │      sm: ext_m3
 *  │                           │                       │                 │             │                      │  │               │     │      dm: mac_a
 *  │                           │                       │                 │             │                      │  │privnet-fib    │◄────┼────  sip: ip4_3
 *  │                           │                       │                 │             │                      │  │snat/dnat      │     │      dip: ip4_1
 *  │                           │                       │                 │             │                      │  │enforce seg    │     │
 *  │                           │                       │                 │             │                      │  └───────┬───────┘     │
 *  │                           │                       │                 │             │                      │          │             │
 *  │                           │                       │                 │             │                      │          ▼             │
 *  │                           │                       │                 │             │                      │    sm: ext_m3          │
 *  │                           │                       │                 │             │                      │    dm: mac_a           │
 *  │                           │                       │                 │             │                      │    sip: ip4_pip3       │
 *  │                           │                       │                 │             │                      │    dip: ip4_pip1       │
 *  │                           │                       │                 │             │                      │          │             │
 *  │                           │                       │                 │             │                      │          ▼             │
 *  │                           │                       │┌──────────────┐ │             │                      │  ┌───────────────┐     │
 *  │                           │                       ││privnet ingres│ │             │                      │  │External EP    │     │
 *  │                           │                       ││              │◄┼───────────[─Encapsulated─]─────────┼──┤Egress Policy  │     │
 *  │                           │                       ││privnet pip   │ │             │                      │  │               │     │
 *  │                           │                       ││rev snat/dnat │ │             │                      │  └───────────────┘     │
 *  │                           │                       ││enforce seg   │ │             │                      │                        │
 *  │                           │                       │└──────┬───────┘ │             │                      │                        │
 *  │                           │                       │       │         │             │                      │                        │
 *  │                           │                       │       ▼         │             │                      │                        │
 *  │                           │                       │   sm: lxc_m     │             │                      │                        │
 *  │                           │                       │   dm: mac_a     │             │                      │                        │
 *  │                     ◄─────┼───────────────────────┼── sip: ip4_3    │             │                      │                        │
 *  │                           │                       │   dip: ip4_1    │             │                      │                        │
 *──┼───────────────────────────┼───────────────────────┼─────────────────┼─────────────┼──────────────────────┼────────────────────────┼──────────────────────────
 *
 *	1. ARP/NS Handling
 *		a. In kubernetes cluster, ARP requests from pods are blindly responded by lxc device with its own MAC address.
 *		b. In INB, ARP request coming from external endpoints should only get response for the pods which are in connected
 *			kubernetes cluster. Care must be taken to not attract unroutable traffic to INB.
 *	2. Pod to External EP
 *		a. Traffic from pod comes with dip of external ep ip and source of its own private ip.
 *			- cil_from_container -> enterprise_privnet hook
 *		b. Privnet egress
 *			- lookup for net-id:sip/dip in privnet-fib map
 *			- sip/dip go through stateless nat to their equivalent pod ips.
 *			- segmentation enforcement
 *		c. Packet follows regular Cilium datapath ( via overlay reaches INB )
 *		d. In cil_from_overlay, ingress processing of packet is done. Starting with external EP L3/L4 ingress policy
 *		   checks.
 *		e. Privnet ingress
 *			- lookup in privnet-pip map for pod IP to get private IPs
 *			- sip/dip go through stateless rev-nat back to original IPs.
 *			- ingress segmentation enforced.
 *		f. Packet is redirected out to the attached privnet link.
 *	3. External EP to Pod
 *		a. Packet comes from netdev device ( do_netdev )
 *		b. Privnet egress
 *			Similar to 2.b
 *		c. Similar to 2.c
 *		d. In cil_lxc_policy, regular policy evaluation is done.
 *		e. Privnet ingress ( similar to 2.e )
 *		f. Packet is redirected to lxc device.
 */

DECLARE_CONFIG(bool, privnet_enable,
	       "True if the endpoint is in a non-default network")
DECLARE_CONFIG(__u32, privnet_unknown_sec_id,
	       "The security identifier for unknown network traffic")
DECLARE_CONFIG(__u16, privnet_network_id,
	       "The identifier of the private network")
DECLARE_CONFIG(bool, privnet_bridge_enable,
	       "True if running on network bridge")

/* TODO: Move PRIVNET_MAP_SIZE to enterprise_node_config.h, this is here till we have
 * GO side of map definitions and node defines to set this via config flag.
 */
#define PRIVNET_MAP_SIZE	65536

struct privnet_fib_key {
	struct bpf_lpm_trie_key lpm_key;
	__u16 net_id;
	__u8 family;
	__u8 pad[1];
	union {
		struct {
			__u32		ip4;
			__u32		pad1;
			__u32		pad2;
			__u32		pad3;
		};
		union v6addr	ip6;
	};
};

struct privnet_fib_val {
	__u8 flag_should_arp:1,
		flag_is_subnet_route:1,
		flag_is_static_route:1,
		pad:5;
	__u8 family;
	union {
		struct {
			__u32		ip4;
			__u32		pad1;
			__u32		pad2;
			__u32		pad3;
		};
		union v6addr	ip6;
	};
};

struct privnet_pip_key {
	struct bpf_lpm_trie_key lpm_key;
	__u8 family;
	__u8 pad[3];
	union {
		struct {
			__u32		ip4;
			__u32		pad1;
			__u32		pad2;
			__u32		pad3;
		};
		union v6addr	ip6;
	};
};

struct privnet_pip_val {
	union macaddr mac;
	union {
		struct {
			__u32		ip4;
			__u32		pad1;
			__u32		pad2;
			__u32		pad3;
		};
		union v6addr	ip6;
	};
	__u8 flags;
	__u8 family;
	__u16 net_id;
	__u32 ifindex;
};

static __always_inline int
nat_v4_addr(struct __ctx_buff *ctx, int l3_off, __be32 *old_addr, __be32 *new_addr)
{
	void *data, *data_end;
	struct iphdr *ip4;
	__u8 nexthdr;
	bool has_l4_header;
	__u64 l4_off;
	__wsum sum;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	nexthdr = ip4->protocol;
	has_l4_header = ipfrag_has_l4_header(ipfrag_encode_ipv4(ip4));
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	sum = csum_diff(old_addr, 4, new_addr, 4, 0);
	if (ctx_store_bytes(ctx, ETH_HLEN + l3_off, new_addr, 4, 0) < 0)
		return DROP_WRITE_ERROR;

	if (ipv4_csum_update_by_diff(ctx, ETH_HLEN, sum) < 0)
		return DROP_CSUM_L3;

	if (has_l4_header) {
		int flags = BPF_F_PSEUDO_HDR;
		struct csum_offset csum = {};

		csum_l4_offset_and_flags(nexthdr, &csum);

		/* Amend the L4 checksum due to changing the addresses. */
		if (csum.offset &&
		    csum_l4_replace(ctx, l4_off, &csum, 0, sum, flags) < 0)
			return DROP_CSUM_L4;
	}

	return CTX_ACT_OK;
}

static __always_inline int
nat_v6_addr(struct __ctx_buff *ctx, int l3_off, union v6addr *new_addr)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	if (ctx_store_bytes(ctx, ETH_HLEN + l3_off, new_addr, 16, 0) < 0)
		return DROP_WRITE_ERROR;

	return CTX_ACT_OK;
}

#define V4_PRIVNET_KEY_LEN (sizeof(__u32) * 8)
#define V6_PRIVNET_KEY_LEN (sizeof(union v6addr) * 8)

#define PRIVNET_FIB_STATIC_PREFIX					\
(8 * (sizeof(struct privnet_fib_key) - sizeof(struct bpf_lpm_trie_key)	\
- sizeof(union v6addr)))
#define PRIVNET_FIB_PREFIX_LEN(PREFIX) (PRIVNET_FIB_STATIC_PREFIX + (PREFIX))

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct privnet_fib_key);
	__type(value, struct privnet_fib_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, PRIVNET_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_privnet_fib __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct privnet_pip_key);
	__type(value, struct privnet_pip_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, PRIVNET_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_privnet_pip __section_maps_btf;

static __always_inline __maybe_unused struct privnet_fib_val *
privnet_fib_lookup4(const void *map, __u16 net_id, __be32 addr) {
	struct privnet_fib_key key = {
		.lpm_key = { PRIVNET_FIB_PREFIX_LEN(V4_PRIVNET_KEY_LEN), {} },
		.net_id = net_id,
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = addr,
	};

	return map_lookup_elem(map, &key);
}

static __always_inline __maybe_unused struct privnet_fib_val *
privnet_fib_lookup6(const void *map, __u16 net_id, union v6addr addr) {
	struct privnet_fib_key key = {
		.lpm_key = { PRIVNET_FIB_PREFIX_LEN(V6_PRIVNET_KEY_LEN), {} },
		.net_id = net_id,
		.family = ENDPOINT_KEY_IPV6,
		.ip6 = addr,
	};

	return map_lookup_elem(map, &key);
}

static __always_inline bool is_privnet_route_entry(const struct privnet_fib_val *val)
{
	if (!val)
		return false;

	return val->flag_is_subnet_route || val->flag_is_static_route;
}

static __always_inline int
enforce_privnet_egress_segmentation(const struct privnet_fib_val *sip_val,
				    const struct privnet_fib_val *dip_val)
{
	if (sip_val && !dip_val) {
		/* The destination mapping not present, where as source has an entry.
		 *
		 * In LXC, this would mean that privnet enabled pod sent out packet to
		 * destination for which there is no endpoint or route associated. To prevent
		 * this packet to leak into underlay it is better to drop it.
		 *
		 * In netdev, this would mean packet came in from connected L2 segment. Src
		 * for some reason believe that destination is in kubernetes cluster. However,
		 * absence of dip_val suggests there is no ep present with that dst ip ( within
		 * private network ). It is better to drop the packet as we have no way to route
		 * to the destination and do not want this packet to leave via INB underlay.
		 */
		return DROP_UNROUTABLE;
	}

	return CTX_ACT_OK;
}

/* privnet_egress_ipv4 can be called as traffic comes from pod to lxc, it should be
 * first thing to happen before processing the packet further in bfp_lxc.
 *
 * It can also be called from connected L2 segment on INB(network bridge), traffic coming
 * from external endpoints or unknown sources which are destined to kubernetes
 * cluster endpoints.
 *
 * Following operations are done at egress
 * - FIB lookup for source and destination in privnet_fib map.
 * - If lookup contains endpoint entries, it will do stateless nat based on the entry.
 * - Basic segmentation check.
 * - Returns lookup result for source and destination.
 */
static __always_inline int privnet_egress_ipv4(struct __ctx_buff *ctx, const void *map,
					       __u16 net_id,
					       const struct privnet_fib_val **src_privnet_entry,
					       const struct privnet_fib_val **dst_privnet_entry)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct privnet_fib_val *sip_val = NULL;
	struct privnet_fib_val *dip_val = NULL;
	int ret = CTX_ACT_OK;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	sip_val = privnet_fib_lookup4(map, net_id, ip4->saddr);
	if (sip_val) {
		if (src_privnet_entry)
			*src_privnet_entry = sip_val;

		if (!is_privnet_route_entry(sip_val)) {
			/* Only nat if entry is for the endpoint, for route
			 * entries, skip natting.
			 */
			ret = nat_v4_addr(ctx, IPV4_SADDR_OFF, &ip4->saddr, &sip_val->ip4);
			if (IS_ERR(ret))
				return ret;
		}
	}

	/* revalidate data before accessing ip4, otherwise verifier will not be happy. */
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	dip_val = privnet_fib_lookup4(map, net_id, ip4->daddr);
	if (dip_val) {
		if (dst_privnet_entry)
			*dst_privnet_entry = dip_val;

		if (!is_privnet_route_entry(dip_val)) {
			/* Only nat if entry is for the endpoint, for route
			 * entries, skip natting.
			 */
			ret = nat_v4_addr(ctx, IPV4_DADDR_OFF, &ip4->daddr, &dip_val->ip4);
			if (IS_ERR(ret))
				return ret;
		}
	}

	/* revalidate data before accessing ip4, otherwise verifier will not be happy. */
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	return enforce_privnet_egress_segmentation(sip_val, dip_val);
}

/* see ipv4 comment */
static __always_inline int privnet_egress_ipv6(struct __ctx_buff *ctx, const void *map,
					       __u16 net_id,
					       const struct privnet_fib_val **src_privnet_entry,
					       const struct privnet_fib_val **dst_privnet_entry)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct privnet_fib_val *sip_val = NULL;
	struct privnet_fib_val *dip_val = NULL;
	union v6addr orig_sip, orig_dip;
	int ret = CTX_ACT_OK;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	ipv6_addr_copy(&orig_sip, (union v6addr *)&ip6->saddr);
	ipv6_addr_copy(&orig_dip, (union v6addr *)&ip6->daddr);

	sip_val = privnet_fib_lookup6(map, net_id, orig_sip);
	if (sip_val) {
		if (src_privnet_entry)
			*src_privnet_entry = sip_val;

		if (!is_privnet_route_entry(sip_val)) {
			ret = nat_v6_addr(ctx, IPV6_SADDR_OFF, &sip_val->ip6);
			if (IS_ERR(ret))
				return ret;
		}
	}

	dip_val = privnet_fib_lookup6(map, net_id, orig_dip);
	if (dip_val) {
		if (dst_privnet_entry)
			*dst_privnet_entry = dip_val;

		if (!is_privnet_route_entry(dip_val)) {
			ret = nat_v6_addr(ctx, IPV6_DADDR_OFF, &dip_val->ip6);
			if (IS_ERR(ret))
				return ret;
		}
	}

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	return enforce_privnet_egress_segmentation(sip_val, dip_val);
}

#define PRIVNET_PIP_STATIC_PREFIX						\
(8 * (sizeof(struct privnet_pip_key) - sizeof(struct bpf_lpm_trie_key)	\
- sizeof(union v6addr)))
#define PRIVNET_PIP_PREFIX_LEN(PREFIX) (PRIVNET_PIP_STATIC_PREFIX + (PREFIX))

static __always_inline __maybe_unused struct privnet_pip_val *
privnet_pip_lookup4(const void *map, __be32 addr) {
	struct privnet_pip_key key = {
		.lpm_key = { PRIVNET_PIP_PREFIX_LEN(V4_PRIVNET_KEY_LEN), {} },
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = addr,
	};

	return map_lookup_elem(map, &key);
}

static __always_inline __maybe_unused struct privnet_pip_val *
privnet_pip_lookup6(const void *map, union v6addr addr) {
	struct privnet_pip_key key = {
		.lpm_key = { PRIVNET_PIP_PREFIX_LEN(V6_PRIVNET_KEY_LEN), {} },
		.family = ENDPOINT_KEY_IPV6,
		.ip6 = addr,
	};

	return map_lookup_elem(map, &key);
}

/*
 * Semantics of enforce_privnet_ingress_segmentation are slightly different from
 * enforce_privnet_egress_segmentation. pip map does not contain route entries,
 * therefore for unknown flow, we do not get route hit.
 */
static __always_inline int
enforce_privnet_ingress_segmentation_at_inb(bool unknown_flow,
					    const struct privnet_pip_val *sip_val,
					    const struct privnet_pip_val *dip_val)
{
	if (unknown_flow) {
		if (sip_val)
			return CTX_ACT_OK;
	} else {
		if (sip_val && dip_val && sip_val->net_id == dip_val->net_id)
			return CTX_ACT_OK;
	}

	return DROP_UNROUTABLE;
}

static __always_inline int
enforce_privnet_ingress_segmentation_at_lxc(bool unknown_flow, __u16 net_id,
					    const struct privnet_pip_val *sip_val,
					    const struct privnet_pip_val *dip_val)
{
	if (unknown_flow) {
		/* For unknown flow, valid dip entry must exist, since traffic in going to pod.
		 * Similarly, dip net_id must match lxc net_id.
		 */
		if (dip_val && net_id == dip_val->net_id)
			return CTX_ACT_OK;
	} else {
		/* For known flows, both sip and dip must exist. And both sip/dip net_ids must
		 * match lxc net_id.
		 */
		if (sip_val && dip_val && net_id == sip_val->net_id && net_id == dip_val->net_id)
			return CTX_ACT_OK;
	}

	return DROP_UNROUTABLE;
}

/* privnet_ingress_ipv4 should be called for privnet enabled endpoints when traffic is going to
 * those endpoints.
 *
 * Following changes are done in this call
 * - Lookup of private IP from PIPs.
 * - Translating pip to private IPs, for both source and destination.
 * - Enforce segmentation to prevent invalid traffic from going to the destination.
 */
static __always_inline int
privnet_ingress_ipv4(struct __ctx_buff *ctx, const void *map, __u16 net_id, bool unknown_flow,
		     const struct privnet_pip_val **src_privnet_entry,
		     const struct privnet_pip_val **dst_privnet_entry)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct privnet_pip_val *sip_val = NULL;
	struct privnet_pip_val *dip_val = NULL;
	int ret = CTX_ACT_OK;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	sip_val = privnet_pip_lookup4(map, ip4->saddr);
	/* Perform translation only if either (a) the network ID matches the expected one, or */
	/* (b) no network ID was configured (i.e., for traffic received from the tunnel). */
	if (sip_val) {
		if (src_privnet_entry)
			*src_privnet_entry = sip_val;

		if (net_id == sip_val->net_id || net_id == 0) {
			ret = nat_v4_addr(ctx, IPV4_SADDR_OFF, &ip4->saddr, &sip_val->ip4);
			if (IS_ERR(ret))
				return ret;
		}
	}

	if (unknown_flow && net_id == 0)
		/* net id is 0 when traffic is received at overlay device, and if
		 * it is unknown flow, then we skip dip as destination IP is not
		 * PIP. This is for traffic coming from k8s cluster into INB
		 * and going out to connected L2 network.
		 */
		goto out;

	/* revalidate data before accessing ip4, otherwise verifier will not be happy. */
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	dip_val = privnet_pip_lookup4(map, ip4->daddr);
	if (dip_val) {
		if (dst_privnet_entry)
			*dst_privnet_entry = dip_val;

		/* Perform dip only if either (a) the network ID matches the expected one, or */
		/* (b) it matches the one of the sip entry. The latter is to ensure that we   */
		/* don't incorrectly dip to an entry that belongs to a different network for  */
		/* traffic received from the tunnel.                                           */
		if (net_id == dip_val->net_id ||
		    (sip_val && sip_val->net_id == dip_val->net_id)) {
			ret = nat_v4_addr(ctx, IPV4_DADDR_OFF, &ip4->daddr, &dip_val->ip4);
			if (IS_ERR(ret))
				return ret;
		}
	}

	/* revalidate data before accessing ip4, otherwise verifier will not be happy. */
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

out:
	/* net_id is set to 0 when packet is received in INB via overlay. */
	return (net_id == 0) ?
		enforce_privnet_ingress_segmentation_at_inb(unknown_flow, sip_val, dip_val) :
		enforce_privnet_ingress_segmentation_at_lxc(unknown_flow, net_id, sip_val, dip_val);
}

static __always_inline int
privnet_ingress_ipv6(struct __ctx_buff *ctx, const void *map, __u16 net_id, bool unknown_flow,
		     const struct privnet_pip_val **src_privnet_entry,
		     const struct privnet_pip_val **dst_privnet_entry)
{
	/* See comments in privnet_pip_ipv4 */
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct privnet_pip_val *sip_val = NULL;
	struct privnet_pip_val *dip_val = NULL;
	union v6addr orig_sip, orig_dip;
	int ret = CTX_ACT_OK;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	ipv6_addr_copy(&orig_sip, (union v6addr *)&ip6->saddr);
	ipv6_addr_copy(&orig_dip, (union v6addr *)&ip6->daddr);

	sip_val = privnet_pip_lookup6(map, orig_sip);
	if (sip_val) {
		if (src_privnet_entry)
			*src_privnet_entry = sip_val;

		if (net_id == sip_val->net_id || net_id == 0) {
			ret = nat_v6_addr(ctx, IPV6_SADDR_OFF, &sip_val->ip6);
			if (IS_ERR(ret))
				return ret;
		}
	}

	if (unknown_flow && net_id == 0)
		goto out;

	dip_val = privnet_pip_lookup6(map, orig_dip);
	if (dip_val) {
		if (dst_privnet_entry)
			*dst_privnet_entry = dip_val;

		if (net_id == dip_val->net_id ||
		    (sip_val && sip_val->net_id == dip_val->net_id)) {
			ret = nat_v6_addr(ctx, IPV6_DADDR_OFF, &dip_val->ip6);
			if (IS_ERR(ret))
				return ret;
		}
	}

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

out:
	return (net_id == 0) ?
		enforce_privnet_ingress_segmentation_at_inb(unknown_flow, sip_val, dip_val) :
		enforce_privnet_ingress_segmentation_at_lxc(unknown_flow, net_id, sip_val, dip_val);
}

static __always_inline int
privnet_policy_egress4(struct __ctx_buff *ctx __maybe_unused,
		       struct iphdr *ip4 __maybe_unused,
		       __u32 dst_sec_identity __maybe_unused,
		       __s8 *ext_err __maybe_unused)
{
	__u8 policy_match_type = POLICY_MATCH_NONE;
	int verdict = CTX_ACT_OK;
	__u16 proxy_port = 0;
	__u8 audited = 0;
	__u32 cookie = 0;

	struct ipv4_ct_tuple tuple = {};
	int l4_off;
	int ret;

	/* calculate tuple */
	tuple.nexthdr = ip4->protocol;
	tuple.saddr = ip4->saddr;
	tuple.daddr = ip4->daddr;
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	ret = ct_extract_ports4(ctx, ip4, ipfrag_encode_ipv4(ip4), l4_off, CT_EGRESS, &tuple);
	if (IS_ERR(ret))
		return ret;
	ipv4_ct_tuple_swap_ports(&tuple);

	verdict = ext_eps_policy_can_egress4(ctx, ip4->saddr, dst_sec_identity, tuple.dport,
					     ip4->protocol, l4_off, &policy_match_type, &audited,
					     ext_err, &proxy_port, &cookie);
	return verdict;
}

static __always_inline int
privnet_policy_ingress4(struct __ctx_buff *ctx,
			struct iphdr *ip4,
			__u32 src_sec_identity,
			__s8 *ext_err)
{
	__u8 policy_match_type = POLICY_MATCH_NONE;
	int verdict = CTX_ACT_OK;
	__u16 proxy_port = 0;
	__u8 audited = 0;
	__u32 cookie = 0;
	int l4_off;
	int ret;
	fraginfo_t fraginfo;
	bool is_untracked_fragment = false;
	struct ipv4_ct_tuple tuple = {};

	fraginfo = ipfrag_encode_ipv4(ip4);
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

#ifndef ENABLE_IPV4_FRAGMENTS
	/* Indicate that this is a datagram fragment for which we cannot
	 * retrieve L4 ports. Do not set flag if we support fragmentation.
	 */
	is_untracked_fragment = ipfrag_is_fragment(fraginfo);
#endif

	tuple.nexthdr = ip4->protocol;
	tuple.saddr = ip4->saddr;
	tuple.daddr = ip4->daddr;
	ret = ct_extract_ports4(ctx, ip4, fraginfo, l4_off, CT_INGRESS, &tuple);
	if (IS_ERR(ret))
		return ret;

	ipv4_ct_tuple_swap_ports(&tuple);

	verdict = ext_eps_policy_can_ingress4(ctx, ip4->daddr, src_sec_identity, tuple.dport,
					      ip4->protocol, l4_off, is_untracked_fragment,
					      &policy_match_type, &audited, ext_err, &proxy_port,
					      &cookie);
	return verdict;
}

static __always_inline int
privnet_policy_egress6(struct __ctx_buff *ctx,
		       struct ipv6hdr *ip6,
		       __u32 dst_sec_identity,
		       __s8 *ext_err __maybe_unused)
{
	__u8 policy_match_type = POLICY_MATCH_NONE;
	int verdict = CTX_ACT_OK;
	__u16 proxy_port = 0;
	__u8 audited = 0;
	__u32 cookie = 0;

	struct ipv6_ct_tuple tuple = {};
	fraginfo_t fraginfo;
	int hdrlen, l4_off, ret;

	tuple.nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen_with_fraginfo(ctx, &tuple.nexthdr, &fraginfo);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = ETH_HLEN + hdrlen;
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&ip6->saddr);
	ipv6_addr_copy(&tuple.daddr, (union v6addr *)&ip6->daddr);

	ret = ct_extract_ports6(ctx, ip6, fraginfo, l4_off, CT_EGRESS, &tuple);
	if (IS_ERR(ret))
		return ret;

	ipv6_ct_tuple_swap_ports(&tuple);

	verdict = ext_eps_policy_can_egress6(ctx, tuple.saddr, dst_sec_identity, tuple.dport,
					     ip6->nexthdr, l4_off, &policy_match_type,
					     &audited, ext_err, &proxy_port, &cookie);

	return verdict;
}

static __always_inline int
privnet_policy_ingress6(struct __ctx_buff *ctx,
			struct ipv6hdr *ip6,
			__u32 src_sec_identity,
			__s8 *ext_err __maybe_unused)
{
	__u8 policy_match_type = POLICY_MATCH_NONE;
	int verdict = CTX_ACT_OK;
	__u16 proxy_port = 0;
	__u8 audited = 0;
	__u32 cookie = 0;

	struct ipv6_ct_tuple tuple = {};
	fraginfo_t fraginfo;
	bool is_untracked_fragment = false;
	int hdrlen, l4_off, ret;

	tuple.nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen_with_fraginfo(ctx, &tuple.nexthdr, &fraginfo);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = ETH_HLEN + hdrlen;
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&ip6->saddr);
	ipv6_addr_copy(&tuple.daddr, (union v6addr *)&ip6->daddr);

#ifndef ENABLE_IPV6_FRAGMENTS
	/* Indicate that this is a datagram fragment for which we cannot
	 * retrieve L4 ports. Do not set flag if we support fragmentation.
	 */
	is_untracked_fragment = ipfrag_is_fragment(fraginfo);
#endif

	ret = ct_extract_ports6(ctx, ip6, fraginfo, l4_off, CT_INGRESS, &tuple);
	if (IS_ERR(ret))
		return ret;
	ipv6_ct_tuple_swap_ports(&tuple);

	verdict = ext_eps_policy_can_ingress6(ctx, tuple.daddr, src_sec_identity, tuple.dport,
					      ip6->nexthdr, l4_off, is_untracked_fragment,
					      &policy_match_type, &audited, ext_err, &proxy_port,
					      &cookie);

	return verdict;
}

#ifdef ENABLE_IPV6
static __always_inline bool ipv6_addr_is_link_local(const union v6addr *ip6addr)
{
	/* fe80::/10: first 10 bits must be 1111111010 */
	return (ip6addr->addr[0] == 0xfe) && ((ip6addr->addr[1] & 0xc0) == 0x80);
}

static __always_inline int
handle_privnet_ns(struct __ctx_buff *ctx, const void *map, const __u16 net_id, bool from_lxc)
{
	union macaddr mac = CONFIG(interface_mac);
	union v6addr tip;
	__u8 type;
	struct privnet_fib_val *val;

	if (icmp6_load_type(ctx, ETH_HLEN + sizeof(struct ipv6hdr), &type) < 0 ||
	    type != ICMP6_NS_MSG_TYPE)
		return CTX_ACT_OK;

	if (ctx_load_bytes(ctx, ETH_HLEN + ICMP6_ND_TARGET_OFFSET, tip.addr,
			   sizeof(((struct ipv6hdr *)NULL)->saddr)) < 0)
		return CTX_ACT_OK;

	if (from_lxc && ipv6_addr_is_link_local(&tip)) {
		/*
		 * Only applicable for LXC.
		 * We are expecting default route from inside the VM as 'default via <some-link-local-address>.
		 * Which means connected VM will send NS for a link local address.
		 * Check target address is 0xfe80 address, if yes then respond with NS.
		 *
		 * TODO: Have a better way to configure link local route inside the VM and only respond to
		 * NS for that address.
		 */
		return icmp6_send_ndisc_adv(ctx, ETH_HLEN, &mac, false);
	}

	val = privnet_fib_lookup6(map, net_id, tip);
	if (!val || !val->flag_should_arp)
		return CTX_ACT_OK;

	return icmp6_send_ndisc_adv(ctx, ETH_HLEN, &mac, false);
}
#endif /* ENABLE_IPv6 */

static __always_inline int
handle_privnet_arp(struct __ctx_buff *ctx, const void *map, const __u16 net_id)
{
	union macaddr mac = CONFIG(interface_mac);
	union macaddr smac;
	__be32 sip, tip;
	struct privnet_fib_val *val;

	/* Prevent the compiler from making (incorrect) assumptions on the content
	 * of the mac variable, and in turn optimizing out the eth_addrcmp(dmac, mac)
	 * check of arp_validate. Otherwise, no response would be generated for
	 * unicast ARP requests.
	 */
	barrier_data(&mac);

	if (!arp_validate(ctx, &mac, &smac, &sip, &tip))
		return CTX_ACT_OK;

	val = privnet_fib_lookup4(map, net_id, tip);
	if (!val || !val->flag_should_arp)
		return CTX_ACT_OK;

	return arp_respond(ctx, &mac, tip, &smac, sip, 0);
};
