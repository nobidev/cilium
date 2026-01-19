/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/enterprise_privnet_config.h"

static __always_inline void enterprise_privnet_to_wireguard(void)
{
	if (!CONFIG(privnet_bridge_enable))
		/* We're not on the bridge. The source is always in PIP space. The
		 * destination is unknown, as it might be encapsulated unknown flow
		 * traffic. Let userspace figure it out.
		 */
		return set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_UNKNOWN_NET_ID);

	/* We're on the bridge. The destination is always in PIP space. The source
	 * is unknown, as it might be encapsulated unknown flow traffic. Let userspace
	 * figure it out.
	 */
	return set_privnet_net_ids(PRIVNET_UNKNOWN_NET_ID, PRIVNET_PIP_NET_ID);
}

static __always_inline void enterprise_privnet_from_wireguard(void)
{
	if (!CONFIG(privnet_bridge_enable))
		/* We're not on the bridge. The destination is always in PIP space.
		 * The source is unknown, as it might be encapsulated unknown flow
		 * traffic. Let userspace figure it out.
		 */
		return set_privnet_net_ids(PRIVNET_UNKNOWN_NET_ID, PRIVNET_PIP_NET_ID);

	/* We're on the bridge. The source is always in PIP space. The destination
	 * is unknown, as it might be encapsulated unknown flow traffic. Let userspace
	 * figure it out.
	 */
	return set_privnet_net_ids(PRIVNET_PIP_NET_ID, PRIVNET_UNKNOWN_NET_ID);
}
