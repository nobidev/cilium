// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package healthchecker

import (
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"k8s.io/apimachinery/pkg/util/duration"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/time"
)

// healthCheck defines the health check target and it's health status.
//
// The targets added to Table[healthCheck] are health checked periodically
// and the results are written back to it.
//
// Note that the fields of this object are exported so that we can JSON marshal
// it into sysdump.
type healthCheck struct {
	Service lb.ServiceName
	Backend lb.L3n4Addr
	Config  HealthCheckConfig

	// Frontends associated with the service. Only includes LoadBalancer frontend
	// addresses.
	Frontends []lb.L3n4Addr

	// UpdatedAt is when the health check configuration was last updated at
	UpdatedAt time.Time

	// ProbedAt is the time when the health check was last performed
	ProbedAt time.Time

	// Healthy is true if the backend is considered Healthy according the Healthy/unhealthy
	// counts and configured thresholds.
	Healthy bool

	// HealthyProbeStreak is the length of healthy probe streak. When this is above
	// [Config.ThresholdHealthy] the backend is considered healthy.
	HealthyProbeStreak uint

	// UnhealthyProbeStreak is the length of the unhealthy probe streak. When this is above
	// [Config.ThresholdUnhealthy] the backend is considered unhealthy.
	UnhealthyProbeStreak uint

	// Message gives additional details on result of the probe
	Message string
}

func (h *healthCheck) clone() *healthCheck {
	h2 := *h
	return &h2
}

func (h *healthCheck) key() healthCheckKey {
	return healthCheckKey{h.Service, h.Backend}
}

// probeAt returns the time when probing should be performed.
func (h *healthCheck) probeAt() time.Time {
	switch {
	case !h.Healthy && !h.ProbedAt.IsZero():
		return h.ProbedAt.Add(h.Config.QuarantineTimeout)
	case !h.ProbedAt.IsZero():
		return h.ProbedAt.Add(h.Config.ProbeInterval)
	default:
		return h.UpdatedAt.Add(h.Config.ProbeInterval)
	}
}

// TableHeader implements statedb.TableWritable.
func (h *healthCheck) TableHeader() []string {
	return []string{
		"Backend",
		"Service",
		"Healthy",
		"HealthyProbeStreak",
		"UnhealthyProbeStreak",
		"Message",
		"Updated",
		"Probed",
		"ProbeIn",
	}
}

// TableRow implements statedb.TableWritable.
func (h *healthCheck) TableRow() []string {
	return []string{
		h.Backend.StringWithProtocol(),
		h.Service.String(),
		strconv.FormatBool(h.Healthy),
		strconv.FormatInt(int64(h.HealthyProbeStreak), 10),
		strconv.FormatInt(int64(h.UnhealthyProbeStreak), 10),
		h.Message,
		duration.HumanDuration(time.Since(h.UpdatedAt)),
		duration.HumanDuration(time.Since(h.ProbedAt)),
		duration.HumanDuration(time.Until(h.probeAt())),
	}
}

var _ statedb.TableWritable = &healthCheck{}

type healthCheckKey struct {
	ServiceName lb.ServiceName
	Backend     lb.L3n4Addr
}

func (k healthCheckKey) Key() index.Key {
	return slices.Concat(k.ServiceName.Key(), k.Backend.Bytes())
}

const (
	healthCheckTableName = "service-healthchecks"
)

var (
	healthCheckAddressIndex = statedb.Index[*healthCheck, healthCheckKey]{
		Name: "address",
		FromObject: func(obj *healthCheck) index.KeySet {
			return index.NewKeySet(healthCheckKey{obj.Service, obj.Backend}.Key())
		},
		FromKey: healthCheckKey.Key,
		FromString: func(key string) (index.Key, error) {
			// String keys have form 1.2.3.4:80/TCP=default/somesvc
			beStr, svcStr, found := strings.Cut(key, "=")
			var be lb.L3n4Addr
			if err := be.ParseFromString(beStr); err != nil {
				return index.Key{}, err
			}
			if !found {
				// No separator found, just search by address
				return be.Bytes(), nil
			}
			namespace, name, found := strings.Cut(svcStr, "/")
			if !found {
				name = namespace
				namespace = ""
			}
			return healthCheckKey{lb.NewServiceName(namespace, name), be}.Key(), nil
		},
		Unique: true,
	}

	healthCheckServiceNameIndex = statedb.Index[*healthCheck, string]{
		Name: "service",
		FromObject: func(obj *healthCheck) index.KeySet {
			return index.NewKeySet(index.Stringer(obj.Service))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     false,
	}
)

func healthCheckByServiceAndBackend(svc lb.ServiceName, beAddr lb.L3n4Addr) statedb.Query[*healthCheck] {
	return healthCheckAddressIndex.Query(healthCheckKey{svc, beAddr})
}

func healthCheckByService(svc lb.ServiceName) statedb.Query[*healthCheck] {
	return healthCheckServiceNameIndex.Query(svc.String())
}

func newHealthCheckTable(db *statedb.DB) (statedb.RWTable[*healthCheck], error) {
	return statedb.NewTable(
		db,
		healthCheckTableName,
		healthCheckAddressIndex,
		healthCheckServiceNameIndex,
	)
}
