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

	"encoding/binary"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	"github.com/vmware/go-ipfix/pkg/registry"
)

var (
	ieFields = []string{
		"sourceIPv4Address",
		"destinationIPv4Address",
		"sourceTransportPort",
		"destinationTransportPort",
		"protocolIdentifier",
		"packetTotalCount",
		"octetTotalCount",
	}
)

func senderLoadRegistry() {
	registry.LoadRegistry()
}

func populateDataRecordElements(flkey FlowLogKey, flentry FlowLogEntry) []entities.InfoElementWithValue {
	bytes := []byte(flkey)
	srcIP := net.IP(bytes[0:4])
	dstIP := net.IP(bytes[4:8])
	srcPort := binary.BigEndian.Uint16(bytes[8:10])
	dstPort := binary.BigEndian.Uint16(bytes[10:12])
	protocol := bytes[12]

	packetsTotal := flentry.Packets
	bytesTotal := flentry.Bytes

	elements := make([]entities.InfoElementWithValue, 0)
	for _, name := range ieFields {
		element, _ := registry.GetInfoElement(name, registry.IANAEnterpriseID)
		var ie entities.InfoElementWithValue
		switch name {
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

func openConnectionToCollector(config *Config) (*exporter.ExportingProcess, error) {
	if config.LoadbalancerFlowLogsCollectorAddress == "" {
		return nil, fmt.Errorf("LoadbalancerFlowLogsCollectorAddress is not set")
	}

	return exporter.InitExportingProcess(exporter.ExporterInput{
		CollectorAddress:    config.LoadbalancerFlowLogsCollectorAddress,
		CollectorProtocol:   "tcp",
		ObservationDomainID: 1,
		TempRefTimeout:      0,
	})
}

func negotiateTemplate(exportingProcess *exporter.ExportingProcess) (uint16, error) {
	templateID := exportingProcess.NewTemplateID()
	log.Debug(fmt.Sprintf("templateID: %v", templateID))

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
	log.Info(fmt.Sprintf("Sent %d bytes of template", bytesWritten))

	return templateID, nil
}

func send(exportingProcess *exporter.ExportingProcess, templateID uint16, bigTable FlowLogTable, keys []FlowLogKey) (uint64, error) {
	dataSet := entities.NewSet(false)
	dataSet.PrepareSet(entities.Data, templateID)

	for i := range keys {
		key := keys[i]
		dataSet.AddRecord(populateDataRecordElements(key, bigTable[key]), templateID)
	}

	bytesWritten, err := exportingProcess.SendSet(dataSet)
	if err != nil {
		return 0, fmt.Errorf("Got error when sending Data Set: %w", err)
	}

	return uint64(bytesWritten), nil
}

func sendData(exportingProcess *exporter.ExportingProcess, templateID uint16, bigTable FlowLogTable) error {
	total := 0
	totalBytesWritten := uint64(0)
	chunkLenMax := 10
	keys := make([]FlowLogKey, chunkLenMax)

	for key := range bigTable {
		i := (total % chunkLenMax)
		keys[i] = key
		total += 1
		chunkLen := i + 1

		if chunkLen == chunkLenMax || total == len(bigTable) {
			if bytesWritten, err := send(exportingProcess, templateID, bigTable, keys[:chunkLen]); err != nil {
				return err
			} else {
				totalBytesWritten += bytesWritten
			}
		}
	}
	log.Info(fmt.Sprintf("Sent %d bytes of data", totalBytesWritten))

	return nil
}

func sendFlowLogs(bigTable FlowLogTable, config *Config) error {
	exportingProcess, err := openConnectionToCollector(config)
	if err != nil {
		return fmt.Errorf("Got error when connecting to ipfix collector: %w", err)
	}
	defer exportingProcess.CloseConnToCollector()

	templateID, err := negotiateTemplate(exportingProcess)
	if err != nil {
		return fmt.Errorf("Got error when sending Template Set: %w", err)
	}

	return sendData(exportingProcess, templateID, bigTable)
}
