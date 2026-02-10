//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package client

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

type (
	// ConnFactoryFn is the type of the function returning a grpc client connection
	// for a given target node.
	ConnFactoryFn func(target tables.INBNode) (*grpc.ClientConn, error)
)

func NewDefaultConnFactory() ConnFactoryFn {
	return func(target tables.INBNode) (*grpc.ClientConn, error) {
		return Dial(target.HealthAddress())
	}
}

// Dial returns a gRPC client connection using the default privnet settings.
func Dial(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	opts = append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, opts...)
	return grpc.NewClient(target, opts...)
}
