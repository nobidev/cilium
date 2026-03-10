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
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/statedb"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/api/v1"
	grpcclient "github.com/cilium/cilium/enterprise/pkg/privnet/grpc/client"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// GRPCConnFactoryFn dials a gRPC connection to the target INB node.
type GRPCConnFactoryFn func(target tables.INBNode) (*grpc.ClientConn, error)

// GRPCRelayFactory provides gRPC-backed DHCP relays for workloads.
type GRPCRelayFactory struct {
	Log     *slog.Logger
	DB      *statedb.DB
	INBs    statedb.Table[tables.INB]
	Factory GRPCConnFactoryFn
}

// RelayFor implements RelayFactory.
func (f *GRPCRelayFactory) RelayFor(lw *tables.LocalWorkload) (Relayer, error) {
	if lw == nil {
		return nil, errors.New("local workload is nil")
	}
	if lw.Subnet == "" {
		return nil, fmt.Errorf("subnet missing on local workload %d", lw.EndpointID)
	}

	factory := f.Factory
	if factory == nil {
		factory = func(target tables.INBNode) (*grpc.ClientConn, error) {
			return grpcclient.Dial(target.HealthAddress())
		}
	}
	return &grpcRelay{
		log:     f.Log,
		db:      f.DB,
		inbs:    f.INBs,
		factory: factory,
		network: tables.NetworkName(lw.Interface.Network),
		subnet:  lw.Subnet,
	}, nil
}

type grpcRelay struct {
	log     *slog.Logger
	db      *statedb.DB
	inbs    statedb.Table[tables.INB]
	factory GRPCConnFactoryFn
	network tables.NetworkName
	subnet  tables.SubnetName
}

// Relay forwards the DHCP request to the active INB via gRPC.
func (r *grpcRelay) Relay(ctx context.Context, waitTime time.Duration, req *dhcpv4.DHCPv4) ([]*dhcpv4.DHCPv4, error) {
	if req == nil {
		return nil, errors.New("dhcp request is nil")
	}
	if r.network == "" {
		return nil, errors.New("network is required")
	}
	if r.subnet == "" {
		return nil, errors.New("subnet is required")
	}
	if waitTime <= 0 {
		return nil, errors.New("wait time is required")
	}
	if r.factory == nil {
		return nil, errors.New("gRPC connection factory is required")
	}
	if r.log != nil {
		r.log.Info("Relaying DHCP request via gRPC",
			logfields.Network, r.network,
			logfields.Type, req.MessageType(),
			logfields.Xid, req.TransactionID,
			logfields.Chaddr, req.ClientHWAddr,
		)
	}

	txn := r.db.ReadTxn()
	inb, _, found := r.inbs.Get(txn, tables.INBsByNetworkAndRole(r.network, tables.INBRoleActive))
	if !found {
		if r.log != nil {
			r.log.Info("Active INB not found for DHCP relay", logfields.Network, r.network)
		}
		return nil, fmt.Errorf("active INB not found for network %q", r.network)
	}

	conn, err := r.factory(inb.Node)
	if err != nil {
		if r.log != nil {
			r.log.Info("Failed to dial INB for DHCP relay",
				logfields.Network, r.network,
				logfields.Target, inb.Node,
				logfields.Error, err,
			)
		}
		return nil, fmt.Errorf("dial INB %s: %w", inb.Node.String(), err)
	}
	defer conn.Close()

	client := api.NewDHCPRelayClient(conn)
	resp, err := client.Relay(ctx, &api.RelayRequest{
		Network:  string(r.network),
		Subnet:   string(r.subnet),
		Request:  req.ToBytes(),
		WaitTime: durationpb.New(waitTime),
	})
	if err != nil {
		if r.log != nil {
			r.log.Info("DHCP gRPC relay request failed",
				logfields.Network, r.network,
				logfields.Target, inb.Node,
				logfields.Error, err,
			)
		}
		return nil, err
	}
	if resp == nil || len(resp.Responses) == 0 {
		if r.log != nil {
			r.log.Info("DHCP gRPC relay returned empty response",
				logfields.Network, r.network,
				logfields.Target, inb.Node,
			)
		}
		return nil, errors.New("empty DHCP response")
	}

	responses := make([]*dhcpv4.DHCPv4, 0, len(resp.Responses))
	for _, payload := range resp.Responses {
		if len(payload) == 0 {
			continue
		}
		parsed, err := dhcpv4.FromBytes(payload)
		if err != nil {
			if r.log != nil {
				r.log.Info("Failed to parse DHCP gRPC response",
					logfields.Network, r.network,
					logfields.Target, inb.Node,
					logfields.Error, err,
				)
			}
			return nil, fmt.Errorf("parse DHCP response: %w", err)
		}
		if r.log != nil {
			r.log.Info("Received DHCP response via gRPC",
				logfields.Network, r.network,
				logfields.Type, parsed.MessageType(),
				logfields.Xid, parsed.TransactionID,
				logfields.IPv4, parsed.YourIPAddr,
			)
		}
		responses = append(responses, parsed)
	}

	if len(responses) == 0 {
		return nil, errors.New("empty DHCP response")
	}
	return responses, nil
}
