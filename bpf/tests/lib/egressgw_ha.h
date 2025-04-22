/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

enum egressgw_ha_test {
	// Ensure that the first HA test doesn't overlap with the last
	// OSS test.
	TEST_HA_SNAT1 = 100,
	TEST_HA_SNAT2,
	TEST_HA_SNAT_EXCL_CIDR,
	TEST_HA_REDIRECT,
	TEST_HA_REDIRECT_EXCL_CIDR,
	TEST_HA_REDIRECT_SKIP_NO_GATEWAY,
	TEST_HA_XDP_REPLY,
	TEST_HA_DROP_NO_EGRESS_IP,
	TEST_STANDALONE_REDIRECT,
	TEST_STANDALONE_SNAT,
};

#define EGRESS_STATIC_PREFIX (sizeof(__be32) * 8)
#define EGRESS_PREFIX_LEN(PREFIX) (EGRESS_STATIC_PREFIX + (PREFIX))

// From https://github.com/isovalent/cilium/commit/74df7db70f538453ff9677ad64d29d726a438d61
#define add_egressgw_ha_policy_entry(_saddr, _daddr, _cidr, _size, _gateway_ips, _egress_ip,	\
				     _egress_ifindex)						\
{												\
	struct egress_gw_ha_policy_key in_key = {						\
		.lpm_key = { EGRESS_PREFIX_LEN(_cidr), {} },					\
		.saddr   = _saddr,								\
		.daddr   = _daddr,								\
	};											\
												\
	struct egress_gw_ha_policy_entry_v2 in_val = {						\
		.size        = _size,								\
		.egress_ip   = _egress_ip,							\
		.gateway_ips = _gateway_ips,							\
		.egress_ifindex = _egress_ifindex,						\
	};											\
												\
	map_update_elem(&cilium_egress_gw_ha_policy_v4_v2, &in_key, &in_val, 0);		\
}

static __always_inline void del_egressgw_ha_policy_entry(__be32 saddr, __be32 daddr, __u8 cidr)
{
	struct egress_gw_ha_policy_key in_key = {
		.lpm_key = { EGRESS_PREFIX_LEN(cidr), {} },
		.saddr   = saddr,
		.daddr   = daddr,
	};

	map_delete_elem(&cilium_egress_gw_ha_policy_v4_v2, &in_key);
}
