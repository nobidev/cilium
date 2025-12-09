//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package alignchecker

import (
	"github.com/cilium/cilium/enterprise/pkg/maps/egressmapha"
	"github.com/cilium/cilium/enterprise/pkg/maps/encryptionpolicymap"
	"github.com/cilium/cilium/enterprise/pkg/maps/extepspolicy"
	"github.com/cilium/cilium/enterprise/pkg/maps/privnet"
)

func init() {
	for typ, str := range map[string][]any{
		"egress_gw_ha_ct_entry":        {egressmapha.EgressCtVal4{}},
		"egress_gw_ha_policy_key":      {egressmapha.EgressPolicyV2Key4{}},
		"egress_gw_ha_policy_entry_v2": {egressmapha.EgressPolicyV2Val4{}},
		"egress_gw_standalone_key":     {egressmapha.SEGWMapKey4{}},
		"egress_gw_standalone_entry":   {egressmapha.SEGWMapVal4{}},
		"endpoint_key":                 {extepspolicy.Key{}},
		"encryption_policy_key":        {encryptionpolicymap.EncryptionPolicyKey{}},
		"encryption_policy_entry":      {encryptionpolicymap.EncryptionPolicyVal{}},
		"privnet_fib_key":              {privnet.FIBKey{}},
		"privnet_fib_val":              {privnet.FIBVal{}},
		"privnet_pip_key":              {privnet.PIPKey{}},
		"privnet_pip_val":              {privnet.PIPVal{}},
	} {
		toCheck[typ] = append(toCheck[typ], str...)
	}

	for size, str := range map[string][]any{
		"__u32": {extepspolicy.Value{}},
	} {
		toCheckSizes[size] = append(toCheckSizes[size], str...)
	}
}
