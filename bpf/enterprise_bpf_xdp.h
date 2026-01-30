/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/enterprise_privnet_notify_helpers.h"

static __always_inline void enterprise_privnet_xdp_entry(void)
{
	/* The host network is always in PIP space */
	return set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_PIP_NET_ID);
}
