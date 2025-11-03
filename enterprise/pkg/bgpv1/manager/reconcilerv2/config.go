// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/time"
)

const (
	// bgpServiceHealthCheckingFlag is the name of the flag that enables BGP integration with service health-checking
	bgpServiceHealthCheckingFlag = "enable-bgp-svc-health-checking"
	// maintenanceGracefulShutdownCommunityEnabled is the name of the flag that enables sending GRACEFUL_SHUTDOWN BGP community when the node is in maintenance mode
	maintenanceGracefulShutdownCommunityEnabled = "enable-bgp-maintenance-graceful-shutdown-community"
	// maintenanceWithdrawTime is the flag with the time interval for route withdrawal after the node goes into maintenance mode
	maintenanceWithdrawTime = "bgp-maintenance-withdraw-time"
	// routerAdvertisementInterval is the interval between sending unsolicited Router Advertisement messages if BGP unnumbered is enabled
	routerAdvertisementInterval = "router-advertisement-interval"
	// enableLegacySRv6Responder is the flag to enable legacy SRv6 responder. This is disabled by default
	// and you should never enable for the new deployments.
	enableLegacySRv6Responder = "enable-legacy-srv6-responder"
	// enableBGPRouteImport is the flag to enable importing routes from BGP peers into Cilium
	enableBGPRouteImport = "enable-bgp-route-import"
)

var defaultConfig = Config{
	SvcHealthCheckingEnabled:           false,
	MaintenanceGracefulShutdownEnabled: false,
	MaintenanceWithdrawTime:            0,
	RouterAdvertisementInterval:        3 * time.Second, // based on RFC4861 MIN_DELAY_BETWEEN_RAS
	EnableLegacySRv6Responder:          false,
	RouteImportEnabled:                 false,
}

// Config holds configuration options of the enterprise reconcilers.
type Config struct {
	SvcHealthCheckingEnabled           bool          `mapstructure:"enable-bgp-svc-health-checking"`
	MaintenanceGracefulShutdownEnabled bool          `mapstructure:"enable-bgp-maintenance-graceful-shutdown-community"`
	MaintenanceWithdrawTime            time.Duration `mapstructure:"bgp-maintenance-withdraw-time"`
	RouterAdvertisementInterval        time.Duration `mapstructure:"router-advertisement-interval"`
	EnableLegacySRv6Responder          bool          `mapstructure:"enable-legacy-srv6-responder"`
	RouteImportEnabled                 bool          `mapstructure:"enable-bgp-route-import"`
}

// Flags implements cell.Flagger interface to register the configuration options as command-line flags.
func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(bgpServiceHealthCheckingFlag, cfg.SvcHealthCheckingEnabled, "Enables BGP integration with service health-checking")
	flags.Bool(maintenanceGracefulShutdownCommunityEnabled, cfg.MaintenanceGracefulShutdownEnabled, "Enables sending GRACEFUL_SHUTDOWN BGP community when the node is in maintenance mode")
	flags.Duration(maintenanceWithdrawTime, cfg.MaintenanceWithdrawTime, "Withdraws BGP routes in configured time after the node goes into maintenance mode. Does not withdraw if 0.")
	flags.Duration(routerAdvertisementInterval, cfg.RouterAdvertisementInterval, "Interval between sending unsolicited Router Advertisement messages if BGP unnumbered is enabled")
	flags.Bool(enableLegacySRv6Responder, cfg.EnableLegacySRv6Responder, "Enables legacy SRv6 responder. This is disabled by default and you should never enable for the new deployments.")
	flags.MarkHidden(enableLegacySRv6Responder) // Don't let users enable this unless there's a problem
	flags.Bool(enableBGPRouteImport, cfg.RouteImportEnabled, "Enables importing routes from BGP peers into Cilium")
}
