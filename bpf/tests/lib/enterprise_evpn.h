/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

static __always_inline void
vni_add(__u32 vni, __u16 net_id)
{
	struct vni_key key = { .vni = vni };
	struct vni_val val = { .net_id = net_id };

	map_update_elem(&cilium_vni, &key, &val, BPF_ANY);
}

static __always_inline int
vni_del(__u32 vni)
{
	struct vni_key key = { .vni = vni };

	return map_delete_elem(&cilium_vni, &key);
}
