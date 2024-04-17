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
	"github.com/cilium/hive/cell"

	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"service",
	"L7 LB service manager",

	cell.Provide(newLBManager),
	//exhaustruct:ignore
	cell.Config(Config{}),

	cell.ProvidePrivate(
		newILBResource,
	),

	// Invoke an empty function to force its construction.
	cell.Invoke(func(*LBManager) {}),
)

type Config struct {
	Enabled bool `mapstructure:"lb-enabled"`
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("lb-enabled", cfg.Enabled, "TODO")
}

func newILBResource(lc cell.Lifecycle, c client.Clientset, cfg Config) resource.Resource[*isovalent_api_v1alpha1.IsovalentLB] {
	// if !cfg.Enabled {
	// 	return nil
	// }

	return resource.New[*isovalent_api_v1alpha1.IsovalentLB](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentLBList](
			c.IsovalentV1alpha1().IsovalentLBs(""),
		), resource.WithMetric("IsovalentLB"))
}
