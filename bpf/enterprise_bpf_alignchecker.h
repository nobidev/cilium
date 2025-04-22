/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include "lib/egress_gateway_ha.h"
#include "lib/enterprise_encrypt.h"
#include "lib/enterprise_privnet.h"

add_type(struct egress_gw_ha_ct_entry);
add_type(struct egress_gw_ha_policy_key);
add_type(struct egress_gw_ha_policy_entry_v2);
add_type(struct egress_gw_standalone_key);
add_type(struct egress_gw_standalone_entry);
add_type(struct encryption_policy_key);
add_type(struct encryption_policy_entry);
