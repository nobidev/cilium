/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "enterprise_privnet_notify_helpers.h"

#define DROP_EXTENSION \
	__u16   src_net_id; \
	__u16   dst_net_id; \
	__u32   pad;

#define drop_extension_hook(ctx, msg) \
	__drop_extension_hook(&(msg).ext_version, &(msg).src_net_id, &(msg).dst_net_id)

#define NOTIFY_DROP_EXT_VER 1

static __always_inline void __drop_extension_hook(__u8 *extver, __u16 *src_net_id,
						  __u16 *dst_net_id)
{
	get_privnet_net_ids(src_net_id, dst_net_id);
	*extver = NOTIFY_DROP_EXT_VER;
}
