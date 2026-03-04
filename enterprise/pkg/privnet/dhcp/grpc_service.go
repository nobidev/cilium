//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package dhcp

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

type service struct {
	api.UnimplementedDHCPRelayServer

	db      *statedb.DB
	subnets statedb.Table[tables.Subnet]
	log     *slog.Logger
	factory serviceRelayFactoryFunc
}

// serviceRelayFactoryFunc returns a relay implementation for the given relay DHCP configuration.
type serviceRelayFactoryFunc func(mode api.RelayRequest_Mode, relay *api.DHCPRelayModeConfig, iface string) (Relayer, error)

type serviceParams struct {
	cell.In

	DB      *statedb.DB
	Subnets statedb.Table[tables.Subnet]
	Logger  *slog.Logger
	Factory serviceRelayFactoryFunc
}

func newService(in serviceParams) *service {
	return &service{
		db:      in.DB,
		subnets: in.Subnets,
		log:     in.Logger,
		factory: in.Factory,
	}
}

func (s *service) Relay(ctx context.Context, req *api.RelayRequest) (*api.RelayResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is nil")
	}

	network := req.GetNetwork()
	if network == "" {
		return nil, status.Error(codes.InvalidArgument, "network is required")
	}
	subnetName := req.GetSubnet()
	if subnetName == "" {
		return nil, status.Error(codes.InvalidArgument, "subnet is required")
	}

	payload := req.GetRequest()
	if len(payload) == 0 {
		return nil, status.Error(codes.InvalidArgument, "request payload is empty")
	}

	waitTime := req.GetWaitTime()
	if waitTime == nil {
		return nil, status.Error(codes.InvalidArgument, "wait time is required")
	}
	wait := waitTime.AsDuration()
	if wait <= 0 {
		return nil, status.Error(codes.InvalidArgument, "wait time is required")
	}

	mode := req.GetMode()
	relayCfg := req.GetRelay()

	dhcpReq, err := dhcpv4.FromBytes(payload)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid DHCP request")
	}

	txn := s.db.ReadTxn()

	subnet, _, found := s.subnets.Get(txn, tables.SubnetsByNetworkAndName(tables.NetworkName(network), tables.SubnetName(subnetName)))
	if !found {
		return nil, status.Error(codes.FailedPrecondition, "subnet not found")
	}

	if subnet.EgressIfIndex == 0 {
		return nil, status.Error(codes.FailedPrecondition, "network cannot be served by INB")
	}

	relay, err := s.relayForConfig(mode, relayCfg, subnet.EgressIfName)
	if err != nil || relay == nil {
		return nil, status.Error(codes.FailedPrecondition, "relay is not available")
	}
	resps, err := relay.Relay(ctx, wait, dhcpReq)
	if err != nil {
		return nil, status.Error(codes.Unavailable, fmt.Sprintf("relay DHCP: %v", err))
	}
	if len(resps) == 0 {
		return nil, status.Error(codes.Unavailable, "empty DHCP response")
	}

	payloads := make([][]byte, 0, len(resps))
	for _, resp := range resps {
		if resp == nil {
			continue
		}
		payloads = append(payloads, resp.ToBytes())
	}
	if len(payloads) == 0 {
		return nil, status.Error(codes.Unavailable, "empty DHCP response")
	}

	return &api.RelayResponse{Responses: payloads}, nil
}

func (s *service) relayForConfig(mode api.RelayRequest_Mode, relayCfg *api.DHCPRelayModeConfig, iface string) (Relayer, error) {
	if s.factory == nil {
		return nil, fmt.Errorf("relay factory is not available")
	}
	return s.factory(mode, relayCfg, iface)
}
