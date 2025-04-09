// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthcheck

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "egressgateway-ha")
)

const (
	NodeHealthy = iota
	NodeUnhealthy
)

// Cell provides a [Healthchecker] for consumption with hive.
var Cell = cell.Module(
	"egressgateway-healthchecker",
	"Egress Gateway healthchecker",
	cell.Config(defaultConfig),
	cell.Provide(NewHealthchecker),
)

type Config struct {
	// Healthcheck timeout after which an egress gateway is marked not healthy.
	// This also configures the frequency of probes to a value of healthcheckTimeout / 2
	EgressGatewayHAHealthcheckTimeout time.Duration

	ClusterHealthPort int
}

var defaultConfig = Config{
	EgressGatewayHAHealthcheckTimeout: 2 * time.Second,
	ClusterHealthPort:                 defaults.ClusterHealthPort,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("egress-gateway-ha-healthcheck-timeout", def.EgressGatewayHAHealthcheckTimeout, "Healthcheck timeout after which an egress gateway is marked not healthy. This also configures the frequency of probes to a value of healthcheckTimeout / 2")
	flags.Int(option.ClusterHealthPort, defaultConfig.ClusterHealthPort, "")
	flags.MarkHidden(option.ClusterHealthPort)
}

// Event represents a healthchecking event such as a node becoming healthy/unhealthy
type Event struct {
	NodeName string
	Status   int
}

// Healthchecker is the public interface exposed by the egress gateway healthchecker
type Healthchecker interface {
	UpdateNodeList(nodes map[string]nodeTypes.Node, healthy sets.Set[string], probeModeByNode map[string]ProbeMode)
	NodeIsHealthy(nodeName string) bool
	Events() chan Event
	SetProber(node nodeTypes.Node, mode ProbeMode) bool
}

type ProbeMode int

const (
	HTTP ProbeMode = iota
)

func (p ProbeMode) String() string {
	switch p {
	case HTTP:
		return "http"
	default:
		return "unknown"
	}
}

func ParseProbeMode(s string) (ProbeMode, error) {
	switch strings.ToLower(s) {
	case "http":
		return HTTP, nil
	default:
		return 0, errors.New("invalid probe mode: " + s)
	}
}

type healthProber interface {
	runHealthcheckProbe() bool
	mode() ProbeMode
}

type httpProber struct {
	netClient *http.Client
	url       string
}

func (h *httpProber) runHealthcheckProbe() bool {
	r, err := h.netClient.Get(h.url)
	if err != nil {
		return false
	}
	defer r.Body.Close()

	return r.StatusCode == 200
}

func (h *httpProber) mode() ProbeMode {
	return HTTP
}

type nodeStatus struct {
	// lastSuccessfulProbeTimestamp is timestamp of the last successful probe
	lastSuccessfulProbeTimestamp time.Time

	// healthcheckerTickerCh is the channel used to stop the healthcheck goroutine for the node
	healthcheckerTickerCh *time.Ticker

	// healthProber performs health checks on the node using the configured probe mode
	healthProber healthProber
}

type healthchecker struct {
	lock.RWMutex

	Config

	nodes    map[string]nodeTypes.Node
	statuses map[string]*nodeStatus
	events   chan Event
}

// NewHealthchecker returns a new Healthchecker
func NewHealthchecker(config Config) Healthchecker {
	return &healthchecker{
		Config:   config,
		nodes:    make(map[string]nodeTypes.Node),
		statuses: make(map[string]*nodeStatus),
		events:   make(chan Event),
	}
}

// UpdateNodeList updates the internal list of nodes that the healthchecker
// should periodically check. The healthy parameter is a subset of node names
// that should be initialized as healthy even before the first health probe
// verdict is available.
func (h *healthchecker) UpdateNodeList(nodes map[string]nodeTypes.Node, healthy sets.Set[string], probeModeByNode map[string]ProbeMode) {
	h.Lock()
	defer h.Unlock()

	for _, oldNode := range h.nodes {
		if _, ok := nodes[oldNode.Name]; !ok {
			h.stopNodeHealthcheck(oldNode)
		}
	}

	for _, newNode := range nodes {
		if _, ok := h.nodes[newNode.Name]; !ok {
			probeMode := HTTP
			if p, ok := probeModeByNode[newNode.Name]; ok {
				probeMode = p
			}
			h.startNodeHealthcheck(newNode, healthy.Has(newNode.Name), probeMode)
		}
	}

	h.nodes = nodes
}

// NodeIsHealthy returns whether a node is healthy (i.e. last successful probe
// is no older than `h.timeout`) or not
func (h *healthchecker) NodeIsHealthy(nodeName string) bool {
	h.RLock()
	defer h.RUnlock()

	status, ok := h.statuses[nodeName]

	return ok && h.probeTimestampIsFresh(status.lastSuccessfulProbeTimestamp)
}

// Events returns the healthchecker events channel
func (h *healthchecker) Events() chan Event {
	return h.events
}

// SetProber sets the health prober
func (h *healthchecker) SetProber(node nodeTypes.Node, mode ProbeMode) bool {
	h.Lock()
	defer h.Unlock()

	status, ok := h.statuses[node.Name]
	if !ok {
		return false
	}

	if mode == status.healthProber.mode() {
		return false
	}

	status.healthProber = h.createProber(node, mode)

	return true
}

func (h *healthchecker) createProber(node nodeTypes.Node, mode ProbeMode) healthProber {
	switch mode {
	case HTTP:
		return h.createHttpProber(node)
	default:
		return h.createHttpProber(node)
	}
}

func (h *healthchecker) createHttpProber(node nodeTypes.Node) healthProber {
	return &httpProber{
		netClient: &http.Client{Timeout: h.EgressGatewayHAHealthcheckTimeout},
		url: fmt.Sprintf("http://%s/hello",
			net.JoinHostPort(node.GetNodeIP(false).String(), strconv.Itoa(h.ClusterHealthPort))),
	}
}

func (h *healthchecker) probeTimestampIsFresh(probeTimestamp time.Time) bool {
	return time.Since(probeTimestamp) < h.EgressGatewayHAHealthcheckTimeout
}

// Caller must hold h.RwMutex
func (h *healthchecker) startNodeHealthcheck(node nodeTypes.Node, isHealthy bool, probeMode ProbeMode) {
	var (
		tickerCh = time.NewTicker(h.EgressGatewayHAHealthcheckTimeout / 2)
		logger   = log.WithField(logfields.NodeName, node.Name)
	)

	logger.Info("Starting health check for node")

	status := &nodeStatus{
		healthcheckerTickerCh: tickerCh,
		healthProber:          h.createProber(node, probeMode),
	}
	if isHealthy {
		logger.Debug("Node health status is initialized as healthy")
		status.lastSuccessfulProbeTimestamp = time.Now()
	}
	h.statuses[node.Name] = status

	go func() {
		for range tickerCh.C {
			var event *Event

			prober := h.getProber(node)
			if prober == nil {
				continue
			}
			probeSuccessful := prober.runHealthcheckProbe()

			h.Lock()
			nodeStatus, ok := h.statuses[node.Name]
			if !ok {
				h.Unlock()
				continue
			}

			if !probeSuccessful {
				if !h.probeTimestampIsFresh(nodeStatus.lastSuccessfulProbeTimestamp) &&
					!nodeStatus.lastSuccessfulProbeTimestamp.IsZero() {
					logger.Info("Node became unhealthy")

					// When a node becomes unhealthy, set its last successful probe TS to 0 so next
					// time we run this check we'll know the node was already unhealthy (allowing us
					// to skip logging and emitting the event multiple times)
					nodeStatus.lastSuccessfulProbeTimestamp = time.Time{}
					event = &Event{NodeName: node.Name, Status: NodeUnhealthy}
				}
			} else {
				if !h.probeTimestampIsFresh(nodeStatus.lastSuccessfulProbeTimestamp) {
					logger.Info("Node became healthy")
					event = &Event{NodeName: node.Name, Status: NodeHealthy}
				}

				nodeStatus.lastSuccessfulProbeTimestamp = time.Now()
			}

			h.Unlock()

			if event != nil {
				h.events <- *event
			}
		}
	}()
}

func (h *healthchecker) getProber(node nodeTypes.Node) healthProber {
	h.Lock()
	defer h.Unlock()

	nodeStatus, ok := h.statuses[node.Name]
	if !ok {
		return nil
	}

	return nodeStatus.healthProber
}

// Caller must hold h.RwMutex
func (h *healthchecker) stopNodeHealthcheck(node nodeTypes.Node) {
	log.WithField(logfields.NodeName, node.Name).
		Info("Stopping health check for node")

	h.statuses[node.Name].healthcheckerTickerCh.Stop()
	delete(h.statuses, node.Name)
}
