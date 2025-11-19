// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package parser

import (
	"net/netip"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser"
	parserOptions "github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/monitor"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
)

// NewPrivnetParserAdapter returns an extension of the OSS Hubble parser that
// is able to properly parse flows from Private Networks.
//
// The Private Networks feature introduces the concept of "NetIPs", which are
// essentially "virtual IPs" that are then mapped to "PIP", which correspond to
// actually routable pod IPs. Only the "PIP" make sense for OSS Cilium and
// "NetIPs" might overlap with other "PIPs".
//
// To be able to properly parse flows from Private Network, which may contain
// NetIPs, we provide the [PrivnetAdapter], that wraps the OSS [parser.Parser]
// and some hooks as [parser.Option] to translate these NetIPs to pod IPs that
// OSS Hubble can understand.
func NewPrivnetParserAdapter(in struct {
	cell.In
	DB                *statedb.DB
	PrivNetEps        statedb.Table[tables.Endpoint]
	PrivNetMapEntries statedb.Table[*tables.MapEntry]
}) (out struct {
	cell.Out
	ParserOption parserOptions.Option `group:"hubble-parser-options"`
	Adapter      *PrivnetAdapter
}) {
	aptr := &PrivnetAdapter{
		db:                in.DB,
		privNetEps:        in.PrivNetEps,
		privNetMapEntries: in.PrivNetMapEntries,
	}
	out.ParserOption = aptr.parserOpts
	out.Adapter = aptr
	return out
}

// PrivnetAdapter wraps the OSS [parser.Parser] to make it Private Network
// aware.
type PrivnetAdapter struct {
	parser        parser.Decoder
	packetDecoder parserOptions.L34PacketDecoder

	db                *statedb.DB
	privNetEps        statedb.Table[tables.Endpoint]
	privNetMapEntries statedb.Table[*tables.MapEntry]

	perFlowContext
}

type perFlowContext struct {
	srcNetID, dstNetID tables.NetworkID
	isUnkownFlow       bool
	srcNetIP, dstNetIP netip.Addr
}

func (p *PrivnetAdapter) parserOpts(opt *parserOptions.Options) {
	if opt.L34PacketDecoder != nil {
		p.packetDecoder = opt.L34PacketDecoder
	}
	opt.L34PacketDecoder = p
	opt.TraceNotifyDecoder = p.DecodeTraceNotify
	opt.DropNotifyDecoder = p.DecodeDropNotify
	opt.PolicyVerdictNotifyDecoder = p.DecodePolicyVerdictNotify
}

func (p *PrivnetAdapter) Decode(monitorEvent *observerTypes.MonitorEvent) (*v1.Event, error) {

	// Initialize a new per flow context and clear any old state. It will be used in the various
	// hooks along the way.
	// This currently only works because the hubble parser is single threaded. If we ever make
	// the parser multi threaded, we'll need to have a context per execution.
	p.initPerFlowContext()

	// parser.Decode is the upstream OSS parser.
	// For the L34 parser, it will call us via callback hooks in various places, where we'll
	// inject privnet specific parsing logic.
	//
	// In pseudo code it roughly looks like this:
	//
	//  super.Decode() {
	//    // When decoding the monitor events, the OSS code will call us to decode the enterprise
	//    // specific fields in the monitor event. We store this additional information in the
	//    // per flow context.
	//    switch {
	//     DecodeTraceNotify()
	//     DecodeDropNotify()
	//     DecodePolicyVerdictNotify()
	//    }
	//
	//    // When decoding the packet, the OSS parser will again call our `DecodePacket`, which
	//    // will call the upstream packet decoder, but will then translate the decoded flow to
	//    // only contain IPs in the podIP space. This is important, because the OSS code does
	//    // not understand netIPs. We use the previously collected per flow context for this
	//    // translation.
	//    DecodePacket() {
	//      translateToPIP(
	//        super.DecodePacket()
	//      )
	//    }
	//  }
	ev, err := p.parser.Decode(monitorEvent)
	if err != nil {
		return ev, err
	}

	if flow, ok := ev.Event.(*flow.Flow); ok {
		// After we decoded, the flow, we now translate the IPs from the podIP space to the
		// NetIP space, when applicable. For the user, the NetIP space is the "real" IP space
		// and they will want to see the IP they actually assigned to their pod/VM.
		// This is relevant for both L34 and L7 packets.
		p.translateToNetIP(flow)
	}
	return ev, err
}

func (p *PrivnetAdapter) initPerFlowContext() {
	p.perFlowContext = perFlowContext{}
}

// DecodeTraceNotify implements options.TraceNotifyDecoder.
func (p *PrivnetAdapter) DecodeTraceNotify(data []byte, decoded *flow.Flow) (*monitor.TraceNotify, error) {
	etn := monitor.EnterpriseTraceNotify{}
	err := etn.Decode(data)
	if err != nil {
		return nil, err
	}

	// Extract netIDs from the message.
	// If the source Identity is 99, we're definitely in the "unknown flow" case
	p.srcNetID = tables.NetworkID(etn.SrcNetID)
	p.dstNetID = tables.NetworkID(etn.DstNetID)
	p.isUnkownFlow = etn.SrcLabel == identity.ReservedPrivnetUnknownFlow

	etn.SrcLabel = interpretSourceId(etn.SrcLabel)
	return &etn.TraceNotify, nil
}

// DecodeDropNotify implements options.DropNotifyDecoder.
func (p *PrivnetAdapter) DecodeDropNotify(data []byte, decoded *flow.Flow) (*monitor.DropNotify, error) {
	edn := monitor.EnterpriseDropNotify{}
	err := edn.Decode(data)
	if err != nil {
		return nil, err
	}

	// Extract netIDs from the message.
	// If the source Identity is 99, we're definitely in the "unknown flow" case
	p.srcNetID = tables.NetworkID(edn.SrcNetID)
	p.dstNetID = tables.NetworkID(edn.DstNetID)
	p.isUnkownFlow = edn.SrcLabel == identity.ReservedPrivnetUnknownFlow

	edn.SrcLabel = interpretSourceId(edn.SrcLabel)
	return &edn.DropNotify, nil
}

// DecodePolicyVerdictNotify implements options.PolicyVerdictNotifyDecoder.
func (p *PrivnetAdapter) DecodePolicyVerdictNotify(data []byte, decoded *flow.Flow) (*monitor.PolicyVerdictNotify, error) {
	epvn := monitor.EnterprisePolicyVerdictNotify{}
	err := epvn.Decode(data)
	if err != nil {
		return nil, err
	}

	// Note: we should never get a PolicyVerdictNotify without valid network ids, and we
	// should never emit policy verdict messages with half translated flows.
	p.srcNetID = tables.NetworkID(epvn.SrcNetID)
	p.dstNetID = tables.NetworkID(epvn.DstNetID)
	return &epvn.PolicyVerdictNotify, nil
}

func interpretSourceId(id identity.NumericIdentity) identity.NumericIdentity {
	// For the rest of the Parser, ReservedPrivnetUnknownFlow is the same as the unknown identity.
	if id == identity.ReservedPrivnetUnknownFlow {
		return identity.IdentityUnknown
	}
	return id
}

// DecodePacket implements options.PacketDecoder.
// The OSS L34 parser will call us when decoding the actual packet. We'll pass it on to the existing packet decoder, and will the translate all
// NetIPs to PIPs before returning it to the OSS L34 parser, because it can only understand PIPs.
func (p *PrivnetAdapter) DecodePacket(
	payload []byte, decoded *flow.Flow,
	isL3Device bool, isIPv6 bool, isVXLAN bool, isGeneve bool,
) (netip.Addr, netip.Addr, uint16, uint16, error) {
	// Decode the packet with the upstream decoder
	sourceIP, destinationIP, sourcePort, destinationPort, err := p.packetDecoder.DecodePacket(payload, decoded, isL3Device, isIPv6, isVXLAN, isGeneve)
	if err != nil {
		// Not much we can do in an error case. Just return it
		return sourceIP, destinationIP, sourcePort, destinationPort, err
	}
	// We're in the "unknown flow" case if the source sec ID or the tunnel ID is 99
	p.isUnkownFlow = p.isUnkownFlow || decoded.GetTunnel().GetVni() == identity.ReservedPrivnetUnknownFlow.Uint32()

	// Translate the parsed (potentially) NetIPs
	sourceIP, destinationIP = p.translateToPIP(sourceIP, destinationIP, decoded)
	return sourceIP, destinationIP, sourcePort, destinationPort, err
}

func (p *PrivnetAdapter) translateToPIP(srcIP, dstIP netip.Addr, decoded *flow.Flow) (netip.Addr, netip.Addr) {
	if decoded.GetIP() == nil {
		// We don't have any IP information, so privnet logic doesn't apply.
		return srcIP, dstIP
	}

	srcID, dstID := p.resolveNetIDs()

	srcIP, p.srcNetIP = p.resolveIP(srcIP, srcID)
	if srcIP.IsValid() {
		decoded.GetIP().Source = srcIP.String()
	} else {
		decoded.GetIP().Source = ""
	}

	dstIP, p.dstNetIP = p.resolveIP(dstIP, dstID)
	if dstIP.IsValid() {
		decoded.GetIP().Destination = dstIP.String()
	} else {
		decoded.GetIP().Destination = ""
	}

	return srcIP, dstIP
}

func (p *PrivnetAdapter) resolveNetIDs() (tables.NetworkID, tables.NetworkID) {
	if p.isUnkownFlow {
		// In the unknown flow case, the "unknown" NetworkIDs are really unknown. Return the IDs as is
		return p.srcNetID, p.dstNetID
	}

	// If one of the endpoints is in a known network the other is not, and we're not in the "unknown flow" case,
	// the unknown endpoint needs to be in the same network space as the other endpoint.
	switch {
	case p.srcNetID == tables.NetworkIDUnknown && p.dstNetID != tables.NetworkIDUnknown:
		p.srcNetID = p.dstNetID
	case p.dstNetID == tables.NetworkIDUnknown && p.srcNetID != tables.NetworkIDUnknown:
		p.dstNetID = p.srcNetID
	}
	return p.srcNetID, p.dstNetID
}

func (p *PrivnetAdapter) resolveIP(ip netip.Addr, netID tables.NetworkID) (podIP netip.Addr, netIP netip.Addr) {
	if netID == tables.NetworkIDReserved {
		// We're in PIP space. Just return the PIP and so not set the NetIP. We'll look it up later.
		return ip, netip.Addr{}
	}
	if netID == tables.NetworkIDUnknown {
		// We don't have a PIP for this NetIP.
		return netip.Addr{}, ip
	}

	// Find PIP
	tx := p.db.ReadTxn()
	entry, _, ok := p.privNetMapEntries.Get(tx, tables.MapEntriesForEndpointsByIDNetIP(netID, ip))
	if !ok {
		return netip.Addr{}, ip
	}

	return entry.Routing.NextHop, ip
}

// translateToNetIP takes a flow in PIP space and translates it to a NetIP flow, if applicable
func (p *PrivnetAdapter) translateToNetIP(decoded *flow.Flow) {
	ip := decoded.GetIP()
	if ip == nil {
		// No IP information to translate
		return
	}

	// This means we only have NetIP for the source, so the OSS parser was unable to get
	// any endpoint information. Get it separately.
	if p.srcNetIP.IsValid() && ip.GetSource() == "" {
		decoded.Source = p.getNetIPEndpoint(p.srcNetIP)
	}
	// Similarly, of we only have a NetIP for the destination, get the endpoint information
	// based on it.
	if p.dstNetIP.IsValid() && ip.GetDestination() == "" {
		decoded.Destination = p.getNetIPEndpoint(p.dstNetIP)
	}

	srcNetIP, ok := p.mapToNetIPSpace(p.srcNetIP, decoded.IP.Source)
	if ok {
		decoded.IP.Source = srcNetIP.String()
	}

	dstNetIP, ok := p.mapToNetIPSpace(p.dstNetIP, decoded.IP.Destination)
	if ok {
		decoded.IP.Destination = dstNetIP.String()
	}
}

// getNetIPEndpoint resolves the endpoint information for the provided NetIP
func (p *PrivnetAdapter) getNetIPEndpoint(netIP netip.Addr) *flow.Endpoint {
	// For now we treat all "unknown" NetIPs as WORLD. To be revised once policy can give us a better identity.
	return &flow.Endpoint{
		Identity: identity.GetWorldIdentityFromIP(netIP).Uint32(),
		Labels: []string{
			labels.LabelSourceReserved + ":" + identity.GetWorldIdentityFromIP(netIP).String(),
		},
	}
}

func (p *PrivnetAdapter) mapToNetIPSpace(netIP netip.Addr, flowIP string) (netip.Addr, bool) {
	if netIP.IsValid() {
		// We parsed the NetIP in a previous step. We can just reuse it.
		return netIP, true
	}

	pip, err := netip.ParseAddr(flowIP)
	if err != nil {
		// We can't parse the provided IP. Not much we can do about it.
		return netip.Addr{}, false
	}

	ep, _, ok := p.privNetEps.Get(p.db.ReadTxn(), tables.EndpointsByPIP(pip))
	if !ok {
		// There is no NetIP, keep the PIP
		return netip.Addr{}, false
	}
	return ep.Network.IP, true
}
