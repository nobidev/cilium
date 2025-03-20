//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lb

import (
	ossannotation "github.com/cilium/cilium/pkg/annotation"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	lbNodeTypeT1      = "t1"
	lbNodeTypeT2      = "t2"
	lbNodeTypeT1AndT2 = "t1-t2"
)

var defaultT1LabelSelector = slim_metav1.LabelSelector{
	MatchExpressions: []slim_metav1.LabelSelectorRequirement{
		{
			Key:      ossannotation.ServiceNodeExposure,
			Operator: slim_metav1.LabelSelectorOpIn,
			Values: []string{
				lbNodeTypeT1,
				lbNodeTypeT1AndT2,
			},
		},
	},
}

var defaultT2LabelSelector = slim_metav1.LabelSelector{
	MatchExpressions: []slim_metav1.LabelSelectorRequirement{
		{
			Key:      ossannotation.ServiceNodeExposure,
			Operator: slim_metav1.LabelSelectorOpIn,
			Values: []string{
				lbNodeTypeT2,
				lbNodeTypeT1AndT2,
			},
		},
	},
}
