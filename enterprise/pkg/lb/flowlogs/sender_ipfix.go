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
	"log/slog"
	"net"

	"encoding/binary"

	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	"github.com/vmware/go-ipfix/pkg/registry"
)

var ieFieldsV4 = []string{
	"interfaceName",
	"sourceIPv4Address",
	"destinationIPv4Address",
	"sourceTransportPort",
	"destinationTransportPort",
	"protocolIdentifier",
	"packetTotalCount",
	"octetTotalCount",
	"flowStartMilliseconds",
	"flowEndMilliseconds",
}

var ieFieldsV6 = []string{
	"interfaceName",
	"sourceIPv6Address",
	"destinationIPv6Address",
	"sourceTransportPort",
	"destinationTransportPort",
	"protocolIdentifier",
	"packetTotalCount",
	"octetTotalCount",
	"flowStartMilliseconds",
	"flowEndMilliseconds",
}

var _ FlowLogSender = &flowLogIPFixSender{}

// flowLogIPFixSender sends the received flow log entries to an
// IPFix collector endpoint.
type flowLogIPFixSender struct {
	logger             *slog.Logger
	collectorAddresses []string
	collectorProtocol  string
}

func (r *flowLogIPFixSender) Name() string {
	return "ipfix"
}

func (r *flowLogIPFixSender) sendFlowLogsV4(flowLogs FlowLogTableV4) error {
	return r.sendWithFallback(func(exportingProcess *exporter.ExportingProcess) error {
		templateID, err := r.negotiateTemplateV4(exportingProcess)
		if err != nil {
			return fmt.Errorf("got error when sending Template Set: %w", err)
		}

		return r.sendDataV4(exportingProcess, templateID, flowLogs)
	})
}

func (r *flowLogIPFixSender) sendFlowLogsV6(flowLogs FlowLogTableV6) error {
	return r.sendWithFallback(func(exportingProcess *exporter.ExportingProcess) error {
		templateID, err := r.negotiateTemplateV6(exportingProcess)
		if err != nil {
			return fmt.Errorf("got error when sending Template Set: %w", err)
		}

		return r.sendDataV6(exportingProcess, templateID, flowLogs)
	})
}

func (r *flowLogIPFixSender) SendFlowLogs(flowLogsV4 FlowLogTableV4, flowLogsV6 FlowLogTableV6, flowLogsL2 FlowLogTableL2) error {
	if err := r.sendFlowLogsV4(flowLogsV4); err != nil {
		return err
	}
	if err := r.sendFlowLogsV6(flowLogsV6); err != nil {
		return err
	}
	/*
	 * L2 is actually non-standard, implement this if needed
	 */
	return nil
}

func (r *flowLogIPFixSender) loadRegistry() {
	registry.LoadRegistry()
}

func uint32ToIP(x uint32) net.IP {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, x)
	return net.IP(b)
}

func ntohs(x uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, x)
	return binary.LittleEndian.Uint16(b)
}

func (r *flowLogIPFixSender) populateDataRecordElementsV4(flkey FlowLogKeyV4, flentry FlowLogEntry) []entities.InfoElementWithValue {
	elements := make([]entities.InfoElementWithValue, 0)
	for _, name := range ieFieldsV4 {
		element, _ := registry.GetInfoElement(name, registry.IANAEnterpriseID)
		var ie entities.InfoElementWithValue
		switch name {
		case "interfaceName":
			ifName, err := InterfaceByIndex(int(flkey.Ifindex))
			if err != nil {
				r.logger.Error("InterfaceByIndex",
					logfields.Error, err,
					logfields.LinkIndex, flkey.Ifindex)
				ifName = "<unknown>"
			}
			ie = entities.NewStringInfoElement(element, ifName)
		case "sourceIPv4Address":
			ie = entities.NewIPAddressInfoElement(element, uint32ToIP(flkey.SrcAddr))
		case "destinationIPv4Address":
			ie = entities.NewIPAddressInfoElement(element, uint32ToIP(flkey.DstAddr))
		case "sourceTransportPort":
			ie = entities.NewUnsigned16InfoElement(element, flkey.SrcPort)
		case "destinationTransportPort":
			ie = entities.NewUnsigned16InfoElement(element, flkey.DstPort)
		case "protocolIdentifier":
			ie = entities.NewUnsigned8InfoElement(element, flkey.Nexthdr)
		case "packetTotalCount":
			ie = entities.NewUnsigned64InfoElement(element, flentry.Packets)
		case "octetTotalCount":
			ie = entities.NewUnsigned64InfoElement(element, flentry.Bytes)
		case "flowStartMilliseconds":
			ie = entities.NewDateTimeMillisecondsInfoElement(element, uint64(flentry.firstTs.UnixMilli()))
		case "flowEndMilliseconds":
			ie = entities.NewDateTimeMillisecondsInfoElement(element, uint64(flentry.ts.UnixMilli()))

		}
		elements = append(elements, ie)
	}
	return elements
}

func (r *flowLogIPFixSender) populateDataRecordElementsV6(flkey FlowLogKeyV6, flentry FlowLogEntry) []entities.InfoElementWithValue {
	elements := make([]entities.InfoElementWithValue, 0)
	for _, name := range ieFieldsV6 {
		element, _ := registry.GetInfoElement(name, registry.IANAEnterpriseID)
		var ie entities.InfoElementWithValue
		switch name {
		case "interfaceName":
			ifName, err := InterfaceByIndex(int(flkey.Ifindex))
			if err != nil {
				r.logger.Error("InterfaceByIndex",
					logfields.Error, err,
					logfields.LinkIndex, flkey.Ifindex)
				ifName = "<unknown>"
			}
			ie = entities.NewStringInfoElement(element, ifName)
		case "sourceIPv6Address":
			ie = entities.NewIPAddressInfoElement(element, net.IP(flkey.SrcAddr[:]))
		case "destinationIPv6Address":
			ie = entities.NewIPAddressInfoElement(element, net.IP(flkey.DstAddr[:]))
		case "sourceTransportPort":
			ie = entities.NewUnsigned16InfoElement(element, flkey.SrcPort)
		case "destinationTransportPort":
			ie = entities.NewUnsigned16InfoElement(element, flkey.DstPort)
		case "protocolIdentifier":
			ie = entities.NewUnsigned8InfoElement(element, flkey.Nexthdr)
		case "packetTotalCount":
			ie = entities.NewUnsigned64InfoElement(element, flentry.Packets)
		case "octetTotalCount":
			ie = entities.NewUnsigned64InfoElement(element, flentry.Bytes)
		case "flowStartMilliseconds":
			ie = entities.NewDateTimeMillisecondsInfoElement(element, uint64(flentry.firstTs.UnixMilli()))
		case "flowEndMilliseconds":
			ie = entities.NewDateTimeMillisecondsInfoElement(element, uint64(flentry.ts.UnixMilli()))

		}
		elements = append(elements, ie)
	}
	return elements
}

func (r *flowLogIPFixSender) sendWithFallback(send func(*exporter.ExportingProcess) error) error {
	if len(r.collectorAddresses) == 0 {
		return fmt.Errorf("IPFix collector address list is not set")
	}

	var lastErr error
	for _, address := range r.collectorAddresses {
		exportingProcess, err := r.openConnectionToCollector(address)
		if err != nil {
			lastErr = err
			r.logger.Warn("Failed to connect to IPFix collector, trying next",
				logfields.Error, err,
				logfields.Address, address)
			continue
		}

		if err := send(exportingProcess); err != nil {
			exportingProcess.CloseConnToCollector()
			lastErr = err
			r.logger.Warn("Failed to send flow logs to IPFix collector, trying next",
				logfields.Error, err,
				logfields.Address, address)
			continue
		}

		exportingProcess.CloseConnToCollector()
		return nil
	}

	return fmt.Errorf("failed to send flow logs to any IPFix collector: %w", lastErr)
}

func (r *flowLogIPFixSender) openConnectionToCollector(address string) (*exporter.ExportingProcess, error) {
	if address == "" {
		return nil, fmt.Errorf("IPFix collector address is empty")
	}

	return exporter.InitExportingProcess(exporter.ExporterInput{
		CollectorAddress:    address,
		CollectorProtocol:   r.collectorProtocol,
		ObservationDomainID: 1,
		TempRefTimeout:      0,
	})
}

func (r *flowLogIPFixSender) negotiateTemplate(exportingProcess *exporter.ExportingProcess, fields []string) (uint16, error) {
	templateID := exportingProcess.NewTemplateID()
	r.logger.Debug("Negotiate template", logfields.TemplateId, templateID)

	ies := make([]*entities.InfoElement, 0)
	for _, name := range fields {
		ie, _ := registry.GetInfoElement(name, registry.IANAEnterpriseID)
		ies = append(ies, ie)
	}

	templateSet, err := entities.MakeTemplateSet(templateID, ies)
	if err != nil {
		return 0, err
	}

	bytesWritten, err := exportingProcess.SendSet(templateSet)
	if err != nil {
		return 0, err
	}
	r.logger.Info("Sent template bytes", logfields.Bytes, bytesWritten)

	return templateID, nil
}

func (r *flowLogIPFixSender) negotiateTemplateV4(exportingProcess *exporter.ExportingProcess) (uint16, error) {
	return r.negotiateTemplate(exportingProcess, ieFieldsV4)
}

func (r *flowLogIPFixSender) negotiateTemplateV6(exportingProcess *exporter.ExportingProcess) (uint16, error) {
	return r.negotiateTemplate(exportingProcess, ieFieldsV6)
}

func (r *flowLogIPFixSender) sendV4(exportingProcess *exporter.ExportingProcess, templateID uint16, flowLogs FlowLogTableV4, keys []FlowLogKeyV4) (uint64, error) {
	dataSet := entities.NewSet(false)
	dataSet.PrepareSet(entities.Data, templateID)

	for i := range keys {
		key := keys[i]
		dataSet.AddRecord(r.populateDataRecordElementsV4(key, flowLogs[key]), templateID)
	}

	bytesWritten, err := exportingProcess.SendSet(dataSet)
	if err != nil {
		return 0, fmt.Errorf("got error when sending Data Set: %w", err)
	}

	return uint64(bytesWritten), nil
}

func (r *flowLogIPFixSender) sendV6(exportingProcess *exporter.ExportingProcess, templateID uint16, flowLogs FlowLogTableV6, keys []FlowLogKeyV6) (uint64, error) {
	dataSet := entities.NewSet(false)
	dataSet.PrepareSet(entities.Data, templateID)

	for i := range keys {
		key := keys[i]
		dataSet.AddRecord(r.populateDataRecordElementsV6(key, flowLogs[key]), templateID)
	}

	bytesWritten, err := exportingProcess.SendSet(dataSet)
	if err != nil {
		return 0, fmt.Errorf("got error when sending Data Set: %w", err)
	}

	return uint64(bytesWritten), nil
}

func (r *flowLogIPFixSender) sendDataV4(exportingProcess *exporter.ExportingProcess, templateID uint16, flowLogs FlowLogTableV4) error {
	total := 0
	totalBytesWritten := uint64(0)

	// with this chunk length each message should fit inside a minimal possible UDP MTU
	chunkLenMax := 10
	keys := make([]FlowLogKeyV4, chunkLenMax)

	for key := range flowLogs {
		i := (total % chunkLenMax)
		keys[i] = key
		total += 1
		chunkLen := i + 1

		if chunkLen == chunkLenMax || total == len(flowLogs) {
			bytesWritten, err := r.sendV4(exportingProcess, templateID, flowLogs, keys[:chunkLen])
			if err != nil {
				return err
			}

			totalBytesWritten += bytesWritten
		}
	}
	r.logger.Info("Sent data", logfields.Bytes, totalBytesWritten)

	return nil
}

func (r *flowLogIPFixSender) sendDataV6(exportingProcess *exporter.ExportingProcess, templateID uint16, flowLogs FlowLogTableV6) error {
	total := 0
	totalBytesWritten := uint64(0)
	chunkLenMax := len(flowLogs) // this might be adjusted (to ~10? for now) if UDP is to be used, such that each message fits inside minimal possible UDP MTU
	keys := make([]FlowLogKeyV6, chunkLenMax)

	for key := range flowLogs {
		i := (total % chunkLenMax)
		keys[i] = key
		total += 1
		chunkLen := i + 1

		if chunkLen == chunkLenMax || total == len(flowLogs) {
			bytesWritten, err := r.sendV6(exportingProcess, templateID, flowLogs, keys[:chunkLen])
			if err != nil {
				return err
			}

			totalBytesWritten += bytesWritten
		}
	}
	r.logger.Info("Sent data", logfields.Bytes, totalBytesWritten)

	return nil
}
