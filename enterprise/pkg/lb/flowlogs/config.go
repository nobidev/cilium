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

	"github.com/spf13/pflag"

	dpcfgdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/time"
)

//
// control plane
//

type Config struct {
	LoadbalancerFlowLogsEnabled                     bool
	LoadbalancerFlowLogsMapSize                     uint32
	LoadbalancerFlowLogsReportFrequency             uint
	LoadbalancerFlowLogsGcFrequency                 uint
	LoadbalancerFlowLogsReaderQueueSize             uint
	LoadbalancerFlowLogsSender                      string
	LoadbalancerFlowLogsSenderIpfixCollectorAddress string
	LoadbalancerFlowLogsSenderProtocol              string
}

var defaultConfig = Config{
	LoadbalancerFlowLogsEnabled:                     false,
	LoadbalancerFlowLogsMapSize:                     200000,
	LoadbalancerFlowLogsReportFrequency:             10,
	LoadbalancerFlowLogsGcFrequency:                 60,
	LoadbalancerFlowLogsReaderQueueSize:             1024,
	LoadbalancerFlowLogsSender:                      "ipfix",
	LoadbalancerFlowLogsSenderIpfixCollectorAddress: "",
	LoadbalancerFlowLogsSenderProtocol:              "udp",
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("loadbalancer-flow-logs-enabled", defaultConfig.LoadbalancerFlowLogsEnabled, "Enables LB Per-packet Flow Logs")
	flags.Uint32("loadbalancer-flow-logs-map-size", defaultConfig.LoadbalancerFlowLogsMapSize, "Select the size of the LB flow log ringbuffer map")
	flags.Uint("loadbalancer-flow-logs-report-frequency", defaultConfig.LoadbalancerFlowLogsReportFrequency, "LB Report Frequency (seconds)")
	flags.Uint("loadbalancer-flow-logs-gc-frequency", defaultConfig.LoadbalancerFlowLogsGcFrequency, "LB Garbage Collection Frequency (seconds)")
	flags.Uint("loadbalancer-flow-logs-reader-queue-size", defaultConfig.LoadbalancerFlowLogsReaderQueueSize, "LB flow log reader queue size")
	flags.String("loadbalancer-flow-logs-sender", defaultConfig.LoadbalancerFlowLogsSender, "Name of the sender where flow logs should be sent to (ipfix, stdout)")
	flags.String("loadbalancer-flow-logs-sender-protocol", defaultConfig.LoadbalancerFlowLogsSenderProtocol, "The protocol to be used when sending flow logs (udp, tcp)")
	flags.String("loadbalancer-flow-logs-sender-ipfix-collector-address", defaultConfig.LoadbalancerFlowLogsSenderIpfixCollectorAddress, "LB Flow Logs IPFix collector address in the IP:port format")
}

func (c *Config) ReportFrequencyDuration() time.Duration {
	return time.Duration(uint(time.Second) * c.LoadbalancerFlowLogsReportFrequency)
}

func (c *Config) GarbageCollectorFrequencyDuration() time.Duration {
	return time.Duration(uint(time.Second) * c.LoadbalancerFlowLogsGcFrequency)
}

//
// datapath
//

const (
	tableSelectorName = "cilium_fl_table_in_use"
	errorsMapName     = "cilium_fl_errors"
	flv4Map1Name      = "cilium_fl_v4_1"
	flv4Map2Name      = "cilium_fl_v4_2"
	flv6Map1Name      = "cilium_fl_v6_1"
	flv6Map2Name      = "cilium_fl_v6_2"
	fll2Map1Name      = "cilium_fl_l2_1"
	fll2Map2Name      = "cilium_fl_l2_2"
)

func datapathConfigProvider(config Config) dpcfgdef.NodeFnOut {
	return dpcfgdef.NewNodeFnOut(func() (dpcfgdef.Map, error) {
		output := make(dpcfgdef.Map)
		if config.LoadbalancerFlowLogsEnabled {
			output["LB_FLOW_LOGS_ENABLED"] = "1"

			output["CILIUM_LB_FLOW_LOG_TABLE_MAP"] = tableSelectorName
			output["CILIUM_LB_FLOW_LOG_ERRORS_MAP"] = errorsMapName

			output["CILIUM_LB_FLOW_LOG_V4_1_MAP"] = flv4Map1Name
			output["CILIUM_LB_FLOW_LOG_V4_2_MAP"] = flv4Map2Name
			output["CILIUM_LB_FLOW_LOG_V6_1_MAP"] = flv6Map1Name
			output["CILIUM_LB_FLOW_LOG_V6_2_MAP"] = flv6Map2Name
			output["CILIUM_LB_FLOW_LOG_L2_1_MAP"] = fll2Map1Name
			output["CILIUM_LB_FLOW_LOG_L2_2_MAP"] = fll2Map2Name

			output["CILIUM_LB_FLOW_LOG_MAP_SIZE"] = fmt.Sprintf("%d", config.LoadbalancerFlowLogsMapSize)
		}
		return output, nil
	})
}
