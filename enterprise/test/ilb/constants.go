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

import (
	"flag"
	"time"
)

const (
	containerNetwork = "kind-cilium"
)

var flagAppImage = flag.String("app-image", "quay.io/isovalent-dev/lb-healthcheck-app:v0.0.6", "app container image name")
var flagClientImage = flag.String("client-image", "quay.io/isovalent-dev/lb-frr-client:v0.0.2", "client container image name")
var flagUtilsImage = flag.String("utils-image", "busybox:1.37.0-musl", "utils container image name")

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
