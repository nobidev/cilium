//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lbflowlogs

import (
	"fmt"

	"github.com/cilium/cilium/pkg/time"

	"github.com/spf13/pflag"

	dpcfgdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
)

const (
	v4MapName = "cilium_lb_flow_log_rb_v4"
	v6MapName = "cilium_lb_flow_log_rb_v6"
)

type Config struct {
	LoadbalancerFlowLogsEnabled          bool
	LoadbalancerFlowLogsMapSize          uint32
	LoadbalancerFlowLogsReportFrequency  uint
	LoadbalancerFlowLogsGcFrequency      uint
	LoadbalancerFlowLogsCollectorAddress string
}

var defaultConfig = Config{
	LoadbalancerFlowLogsEnabled:          false,
	LoadbalancerFlowLogsMapSize:          32 << 20,
	LoadbalancerFlowLogsReportFrequency:  10,
	LoadbalancerFlowLogsGcFrequency:      61,
	LoadbalancerFlowLogsCollectorAddress: "",
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("loadbalancer-flow-logs-enabled", defaultConfig.LoadbalancerFlowLogsEnabled, "Enables LB Per-packet Flow Logs")
	flags.Uint32("loadbalancer-flow-logs-map-size", defaultConfig.LoadbalancerFlowLogsMapSize, "Select the size of the LB RB Map")
	flags.Uint("loadbalancer-flow-logs-report-frequency", defaultConfig.LoadbalancerFlowLogsReportFrequency, "LB Report Frequency (seconds)")
	flags.Uint("loadbalancer-flow-logs-gc-frequency", defaultConfig.LoadbalancerFlowLogsGcFrequency, "LB Garbage Collection Frequency (seconds)")
	flags.String("loadbalancer-flow-logs-collector-address", defaultConfig.LoadbalancerFlowLogsCollectorAddress, "LB Flow Logs collector address in the IP:port format")
}

func (c *Config) ReportFrequencyToSeconds() time.Duration {
	return time.Duration(uint(time.Second) * c.LoadbalancerFlowLogsReportFrequency)
}

func (c *Config) GarbageCollectorFrequencyToSeconds() time.Duration {
	return time.Duration(uint(time.Second) * c.LoadbalancerFlowLogsGcFrequency)
}

func datapathNodeHeaderConfigProvider(config Config) dpcfgdef.NodeFnOut {
	return dpcfgdef.NewNodeFnOut(func() (dpcfgdef.Map, error) {
		output := make(dpcfgdef.Map)
		if config.LoadbalancerFlowLogsEnabled {
			output["LB_FLOW_LOGS_ENABLED"] = "1"
			output["CILIUM_LB_FLOW_LOG_RB_V6_MAP"] = v6MapName
			output["CILIUM_LB_FLOW_LOG_RB_V4_MAP"] = v4MapName
			output["CILIUM_LB_FLOW_LOG_RB_MAP_SIZE"] = fmt.Sprintf("%d", config.LoadbalancerFlowLogsMapSize)
		}
		return output, nil
	})
}
