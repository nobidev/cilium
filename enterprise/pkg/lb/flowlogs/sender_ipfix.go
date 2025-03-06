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
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	"github.com/vmware/go-ipfix/pkg/registry"
)

var ieFields = []string{
	"interfaceName",
	"sourceIPv4Address",
	"destinationIPv4Address",
	"sourceTransportPort",
	"destinationTransportPort",
	"protocolIdentifier",
	"packetTotalCount",
	"octetTotalCount",
}

var _ FlowLogSender = &flowLogIPFixSender{}

// flowLogIPFixSender sends the received flow log entries to an
// IPFix collector endpoint.
type flowLogIPFixSender struct {
	logger           *slog.Logger
	collectorAddress string
}

func (r *flowLogIPFixSender) Name() string {
	return "ipfix"
}

func (r *flowLogIPFixSender) SendFlowLogs(flowLogs FlowLogTable) error {
	exportingProcess, err := r.openConnectionToCollector()
	if err != nil {
		return fmt.Errorf("got error when connecting to ipfix collector: %w", err)
	}
	defer exportingProcess.CloseConnToCollector()

	templateID, err := r.negotiateTemplate(exportingProcess)
	if err != nil {
		return fmt.Errorf("got error when sending Template Set: %w", err)
	}

	return r.sendData(exportingProcess, templateID, flowLogs)
}

func (r *flowLogIPFixSender) loadRegistry() {
	registry.LoadRegistry()
}

func (r *flowLogIPFixSender) populateDataRecordElements(flkey FlowLogKey, flentry FlowLogEntry) []entities.InfoElementWithValue {
	bytes := []byte(flkey)
	ifindex := int(binary.NativeEndian.Uint32(bytes[ifindexStart : ifindexStart+ifindexSize]))
	srcIP := net.IP(bytes[saddrStart : saddrStart+saddrSize])
	dstIP := net.IP(bytes[daddrStart : daddrStart+daddrSize])
	srcPort := binary.BigEndian.Uint16(bytes[sportStart : sportStart+sportSize])
	dstPort := binary.BigEndian.Uint16(bytes[dportStart : dportStart+dportSize])
	protocol := bytes[nexthdrStart]

	packetsTotal := flentry.Packets
	bytesTotal := flentry.Bytes

	elements := make([]entities.InfoElementWithValue, 0)
	for _, name := range ieFields {
		element, _ := registry.GetInfoElement(name, registry.IANAEnterpriseID)
		var ie entities.InfoElementWithValue
		switch name {
		case "interfaceName":
			ifName, err := InterfaceByIndex(ifindex)
			if err != nil {
				r.logger.Error("InterfaceByIndex", logfields.Error, err, "ifindex", ifindex)
				ifName = "<unknown>"
			}
			ie = entities.NewStringInfoElement(element, ifName)
		case "sourceIPv4Address":
			ie = entities.NewIPAddressInfoElement(element, srcIP)
		case "destinationIPv4Address":
			ie = entities.NewIPAddressInfoElement(element, dstIP)
		case "sourceTransportPort":
			ie = entities.NewUnsigned16InfoElement(element, srcPort)
		case "destinationTransportPort":
			ie = entities.NewUnsigned16InfoElement(element, dstPort)
		case "protocolIdentifier":
			ie = entities.NewUnsigned8InfoElement(element, protocol)
		case "packetTotalCount":
			ie = entities.NewUnsigned64InfoElement(element, packetsTotal)
		case "octetTotalCount":
			ie = entities.NewUnsigned64InfoElement(element, bytesTotal)
		}
		elements = append(elements, ie)
	}
	return elements
}

func (r *flowLogIPFixSender) openConnectionToCollector() (*exporter.ExportingProcess, error) {
	if r.collectorAddress == "" {
		return nil, fmt.Errorf("IPFix collector address is not set")
	}

	return exporter.InitExportingProcess(exporter.ExporterInput{
		CollectorAddress:    r.collectorAddress,
		CollectorProtocol:   "tcp",
		ObservationDomainID: 1,
		TempRefTimeout:      0,
	})
}

func (r *flowLogIPFixSender) negotiateTemplate(exportingProcess *exporter.ExportingProcess) (uint16, error) {
	templateID := exportingProcess.NewTemplateID()
	r.logger.Debug("Negotiate template", "templateID", templateID)

	ies := make([]*entities.InfoElement, 0)
	for _, name := range ieFields {
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
	r.logger.Info("Sent template bytes", "bytes", bytesWritten)

	return templateID, nil
}

func (r *flowLogIPFixSender) send(exportingProcess *exporter.ExportingProcess, templateID uint16, flowLogs FlowLogTable, keys []FlowLogKey) (uint64, error) {
	dataSet := entities.NewSet(false)
	dataSet.PrepareSet(entities.Data, templateID)

	for i := range keys {
		key := keys[i]
		dataSet.AddRecord(r.populateDataRecordElements(key, flowLogs[key]), templateID)
	}

	bytesWritten, err := exportingProcess.SendSet(dataSet)
	if err != nil {
		return 0, fmt.Errorf("got error when sending Data Set: %w", err)
	}

	return uint64(bytesWritten), nil
}

func (r *flowLogIPFixSender) sendData(exportingProcess *exporter.ExportingProcess, templateID uint16, flowLogs FlowLogTable) error {
	total := 0
	totalBytesWritten := uint64(0)
	chunkLenMax := 10
	keys := make([]FlowLogKey, chunkLenMax)

	for key := range flowLogs {
		i := (total % chunkLenMax)
		keys[i] = key
		total += 1
		chunkLen := i + 1

		if chunkLen == chunkLenMax || total == len(flowLogs) {
			bytesWritten, err := r.send(exportingProcess, templateID, flowLogs, keys[:chunkLen])
			if err != nil {
				return err
			}

			totalBytesWritten += bytesWritten
		}
	}
	r.logger.Info("Sent data", "bytes", totalBytesWritten)

	return nil
}
