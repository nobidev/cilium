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
	"net"
	"strconv"
	"strings"

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
	flags.String("loadbalancer-flow-logs-sender-ipfix-collector-address", defaultConfig.LoadbalancerFlowLogsSenderIpfixCollectorAddress, "Comma-separated list of IP:port, [IPv6]:port, or DNS:port addresses for the IPFix collector")
}

func (c *Config) ReportFrequencyDuration() time.Duration {
	return time.Duration(uint(time.Second) * c.LoadbalancerFlowLogsReportFrequency)
}

func (c *Config) GarbageCollectorFrequencyDuration() time.Duration {
	return time.Duration(uint(time.Second) * c.LoadbalancerFlowLogsGcFrequency)
}

func (c Config) validate() error {
	if !c.LoadbalancerFlowLogsEnabled {
		return nil
	}
	if c.LoadbalancerFlowLogsSender == "stdout" {
		return nil
	}
	if err := validateCollectorProtocol(c.LoadbalancerFlowLogsSenderProtocol); err != nil {
		return fmt.Errorf("invalid loadbalancer-flow-logs-sender-protocol: %w", err)
	}

	collectors, err := parseCollectorAddresses(c.LoadbalancerFlowLogsSenderIpfixCollectorAddress)
	if err != nil {
		return err
	}
	if len(collectors) == 0 {
		return fmt.Errorf("loadbalancer-flow-logs-sender-ipfix-collector-address must be set when loadbalancer-flow-logs-sender is %q", c.LoadbalancerFlowLogsSender)
	}

	return nil
}

func parseCollectorAddresses(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	parts := strings.Split(raw, ",")
	addrs := make([]string, 0, len(parts))
	for i, part := range parts {
		entry := strings.TrimSpace(part)
		if entry == "" {
			return nil, fmt.Errorf("collector address list contains an empty entry at position %d", i+1)
		}
		if strings.Count(entry, ":") > 1 && !strings.Contains(entry, "[") {
			return nil, fmt.Errorf("collector address %q is missing brackets around IPv6 address (use [addr]:port)", entry)
		}
		host, port, err := net.SplitHostPort(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid collector address %q: %w", entry, err)
		}
		if host == "" {
			return nil, fmt.Errorf("collector address %q is missing host", entry)
		}
		if port == "" {
			return nil, fmt.Errorf("collector address %q is missing port", entry)
		}
		if err := validatePort(port); err != nil {
			return nil, fmt.Errorf("collector address %q has invalid port: %w", entry, err)
		}
		if ip := net.ParseIP(host); ip == nil && !isValidHostname(host) {
			return nil, fmt.Errorf("collector address %q has invalid host %q; expected IP (v4/v6) or DNS name", entry, host)
		}

		addrs = append(addrs, entry)
	}

	return addrs, nil
}

func validatePort(raw string) error {
	port, err := strconv.Atoi(raw)
	if err != nil {
		return fmt.Errorf("port must be numeric")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

func validateCollectorProtocol(protocol string) error {
	switch protocol {
	case "udp", "tcp":
		return nil
	default:
		return fmt.Errorf("must be one of: udp, tcp")
	}
}

func isValidHostname(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return false
	}

	labels := strings.SplitSeq(host, ".")
	for label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			if (ch >= 'a' && ch <= 'z') ||
				(ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') ||
				ch == '-' {
				continue
			}
			return false
		}
	}

	return true
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
