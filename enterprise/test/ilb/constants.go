//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import "time"

const (
	containerNetwork = "kind-cilium"
)

const (
	appImage    = "quay.io/isovalent-dev/lb-healthcheck-app:v0.0.6"
	clientImage = "quay.io/isovalent-dev/lb-frr-client:v0.0.2"
	utilsImage  = "busybox:1.37.0-musl"
)

const (
	lbIPPoolName               = "lb-pool"
	globalBGPClusterConfigName = "ilb-test"
)

const (
	shortTimeout     = 30 * time.Second
	longTimeout      = 120 * time.Second
	pollInterval     = 1 * time.Second
	longPollInterval = 5 * time.Second
)
