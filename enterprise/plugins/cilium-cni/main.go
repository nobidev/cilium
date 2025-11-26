//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"runtime"

	"github.com/containernetworking/cni/pkg/skel"
	cniVersion "github.com/containernetworking/cni/pkg/version"

	_ "github.com/cilium/cilium/enterprise/fips"
	"github.com/cilium/cilium/enterprise/plugins/cilium-cni/pkg/multinetwork"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/version"
	"github.com/cilium/cilium/plugins/cilium-cni/cmd"
)

func init() {
	runtime.LockOSThread()
}

func main() {
	// slogloggercheck: the logger has been initialized with default settings
	logger := logging.DefaultSlogLogger.With(logfields.LogSubsys, "cilium-cni")
	c := cmd.NewCmd(logger, cmd.WithEPConfigurator(multinetwork.NewEndpointConfigurator()))
	skel.PluginMainFuncs(c.CNIFuncs(),
		cniVersion.PluginSupports("0.1.0", "0.2.0", "0.3.0", "0.3.1", "0.4.0", "1.0.0", "1.1.0"),
		"Cilium CNI plugin (enterprise) "+version.Version)
}
