// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <bpf/config/global.h>
#include <bpf/config/node.h>

#include "lib/common.h"
#include "lib/clustermesh.h" /* required to load cluster_id & cluster_id_max in node config (temporarily) */
#include "lib/enterprise_privnet.h"
#include "lib/enterprise_evpn.h"

/* Attached to the ingress of cilium_evpn device to execute on packets
 * entering the node via the evpn-vxlan tunnel.
 */
__section_entry
int cil_from_evpn(struct __ctx_buff __maybe_unused *ctx)
{
	return CTX_ACT_OK;
}

/* Attached to the egress of cilium_evpn device to execute on packets
 * leaving the node via the evpn-vxlan tunnel.
 */
__section_entry
int cil_to_evpn(struct __ctx_buff __maybe_unused *ctx)
{
	return CTX_ACT_OK;
}
