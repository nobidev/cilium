/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <enterprise_bpf_evpn.c>

#define FROM_EVPN		0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map_evpn __section(".maps") = {
	.values = {
		[FROM_EVPN] = &cil_from_evpn,
	},
};

static __always_inline int
evpn_receive_packet(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, entry_call_map_evpn, FROM_EVPN);
	return TEST_ERROR;
}
