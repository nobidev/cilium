// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package export

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	metricsAPI "github.com/cilium/cilium/pkg/hubble/metrics/api"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

var (
	_ metricsAPI.Plugin  = (*metricsPlugin)(nil)
	_ metricsAPI.Handler = (*metricsHandler)(nil)
)

// registerMetricsHandler registers a new metricsPlugin for flow export in the default registry.
func registerMetricsHandler(handler *metricsHandler) {
	metricsAPI.DefaultRegistry().Register("flow_export", &metricsPlugin{handler: handler})
}

type metricsPlugin struct {
	handler *metricsHandler
}

// NewHandler implements the api.Plugin interface.
func (m *metricsPlugin) NewHandler() metricsAPI.Handler {
	return m.handler
}

// HelpText implements the metricsAPI.Plugin interface.
func (*metricsPlugin) HelpText() string {
	return `export - Generic flow export metrics
Reports metrics related to exporting flows

Metrics:
  hubble_flows_exported_total                Total number of flows exported
  hubble_flows_exported_bytes_total          Number of bytes exported for flows
  hubble_flows_last_exported_timestamp       Timestamp of the most recent flow to be exported

Options:` +
		metricsAPI.ContextOptionsHelp
}

type metricsHandler struct {
	flowsExportedTotal      *prometheus.CounterVec
	flowsExportedBytesTotal *prometheus.CounterVec
	flowsExportTimestamp    *prometheus.GaugeVec
	context                 *metricsAPI.ContextOptions
	AllowList               filters.FilterFuncs
	DenyList                filters.FilterFuncs

	// The metrics handler is referenced by the exporter through a set of hooks
	// at startup regardless of whether it has been initialized by the metrics
	// server or not. To avoid uninitialized access, protect update callpaths
	// with an atomic bool.
	// NOTE: Deinit() only removes collector references from the registry but does
	// not invalidate the collectors, therefore once intialized, the pointers will
	// always be valid. In a racy condition between deinit/init, we could access
	// old collectors and send metrics update that will never get emitted. We accept
	// that caveat and classify it as edge-case/rare, while also avoiding the
	// performance cost of a more involved synchronization strategy.
	initialized atomic.Bool
}

// Init implements the metricsAPI.Handler interface.
func (h *metricsHandler) Init(registry *prometheus.Registry, options *metricsAPI.MetricConfig) error {
	c, err := metricsAPI.ParseContextOptions(options.ContextOptionConfigs)
	if err != nil {
		return err
	}
	h.context = c
	err = h.HandleConfigurationUpdate(options)
	if err != nil {
		return err
	}

	commonLabels := []string{"name"}

	flowsExportedTotalLabels := h.flowExportedLabelNames()
	flowsExportedTotalLabels = append(flowsExportedTotalLabels, commonLabels...)
	h.flowsExportedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsAPI.DefaultPrometheusNamespace,
		Name:      "flows_exported_total",
		Help:      "Total number of flows exported",
	}, flowsExportedTotalLabels)

	h.flowsExportedBytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsAPI.DefaultPrometheusNamespace,
		Name:      "flows_exported_bytes_total",
		Help:      "Number of bytes exported for flows",
	}, commonLabels)

	h.flowsExportTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsAPI.DefaultPrometheusNamespace,
		Name:      "flows_last_exported_timestamp",
		Help:      "Timestamp of the most recent flow to be exported",
	}, commonLabels)

	registry.MustRegister(h.flowsExportedTotal)
	registry.MustRegister(h.flowsExportedBytesTotal)
	registry.MustRegister(h.flowsExportTimestamp)

	h.initialized.Store(true)
	return nil
}

// ListMetricVec implements the metricsAPI.Handler interface.
func (h *metricsHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{
		h.flowsExportedTotal.MetricVec,
	}
}

// Context implements the metricsAPI.Handler interface.
func (h *metricsHandler) Context() *metricsAPI.ContextOptions {
	return h.context
}

// Status implements the metricsAPI.Handler interface.
func (h *metricsHandler) Status() string {
	return h.context.Status()
}

// ProcessFlow implements the metricsAPI.Handler interface.
//
// It is intentionally a no-op since we manually handle updating metrics in exporter.OnExportEvent
// using UpdateMetrics.
func (h *metricsHandler) ProcessFlow(_ context.Context, _ *flowpb.Flow) error { return nil }

func (h *metricsHandler) Deinit(registry *prometheus.Registry) error {
	var errs error
	if !registry.Unregister(h.flowsExportedTotal) {
		errs = errors.Join(errs, fmt.Errorf("failed to unregister metric: %v,", "flows_exported_total"))
	}
	if !registry.Unregister(h.flowsExportedBytesTotal) {
		errs = errors.Join(errs, fmt.Errorf("failed to unregister metric: %v,", "flows_exported_bytes_total"))
	}
	if !registry.Unregister(h.flowsExportTimestamp) {
		errs = errors.Join(errs, fmt.Errorf("failed to unregister metric: %v,", "flows_last_exported_timestamp"))
	}
	return errs
}

func (h *metricsHandler) HandleConfigurationUpdate(cfg *metricsAPI.MetricConfig) error {
	return h.SetFilters(cfg)
}

func (h *metricsHandler) SetFilters(cfg *metricsAPI.MetricConfig) error {
	var err error
	h.AllowList, err = filters.BuildFilterList(context.Background(), cfg.IncludeFilters, filters.DefaultFilters(slog.Default()))
	if err != nil {
		return err
	}
	h.DenyList, err = filters.BuildFilterList(context.Background(), cfg.ExcludeFilters, filters.DefaultFilters(slog.Default()))
	if err != nil {
		return err
	}
	return nil
}

// UpdateFlowMetrics updates the flow metrics.
func (h *metricsHandler) UpdateFlowMetrics(_ context.Context, flow *flowpb.Flow, name string) error {
	if !h.initialized.Load() {
		return nil
	}

	commonLabels := []string{name}
	flowsExportedTotalLabels, err := h.flowExportedLabelValues(flow)
	if err != nil {
		return err
	}
	flowsExportedTotalLabels = append(flowsExportedTotalLabels, commonLabels...)

	h.flowsExportedTotal.WithLabelValues(flowsExportedTotalLabels...).Inc()
	h.flowsExportTimestamp.WithLabelValues(commonLabels...).Set(float64(flow.GetTime().GetSeconds()))
	return nil
}

// updateExportedBytesTotal updates the bytes total metric.
func (h *metricsHandler) updateExportedBytesTotal(byteCount int, name string) {
	if !h.initialized.Load() {
		return
	}
	h.flowsExportedBytesTotal.WithLabelValues(name).Add(float64(byteCount))
}

// WrapWriter wraps the provided writer with a new writer that updates the bytes total metric with
// the number of bytes written.
func (h *metricsHandler) WrapWriter(w io.WriteCloser, name string) io.WriteCloser {
	return byteCounterWriter{w, h, name}
}

func (h *metricsHandler) flowExportedLabelNames() []string {
	labels := []string{"protocol", "type", "subtype", "verdict"}
	labels = append(labels, h.context.GetLabelNames()...)
	return labels
}

func (h *metricsHandler) flowExportedLabelValues(flow *flowpb.Flow) ([]string, error) {
	labelValues, err := h.context.GetLabelValues(flow)
	if err != nil {
		return nil, err
	}

	var typeName, subType string
	eventType := flow.GetEventType().GetType()
	switch eventType {
	case monitorAPI.MessageTypeAccessLog:
		typeName = "L7"
		if l7 := flow.GetL7(); l7 != nil {
			switch {
			case l7.GetDns() != nil:
				subType = "DNS"
			case l7.GetHttp() != nil:
				subType = "HTTP"
			case l7.GetKafka() != nil:
				subType = "Kafka"
			}
		}
	case monitorAPI.MessageTypeDrop:
		typeName = "Drop"
	case monitorAPI.MessageTypeCapture:
		typeName = "Capture"
	case monitorAPI.MessageTypeTrace:
		typeName = "Trace"
		subType = monitorAPI.TraceObservationPoints[uint8(flow.GetEventType().SubType)]
	case monitorAPI.MessageTypePolicyVerdict:
		typeName = "PolicyVerdict"
	default:
		typeName = "Unknown"
		subType = fmt.Sprintf("%d", eventType)
	}

	labels := []string{v1.FlowProtocol(flow), typeName, subType, flow.GetVerdict().String()}
	labels = append(labels, labelValues...)
	return labels, nil
}

type byteCounterWriter struct {
	io.WriteCloser
	metricsHandler *metricsHandler
	name           string
}

func (w byteCounterWriter) Write(p []byte) (int, error) {
	n, err := w.WriteCloser.Write(p)
	w.metricsHandler.updateExportedBytesTotal(n, w.name)
	return n, err
}
