// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package forklift

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"private-networks-forklift",
	"Private Networks Forkift Integration",

	cell.Config(defaultConfig),

	cell.ProvidePrivate(
		// Provides the Read and ReadWrite providers table.
		NewProvidersTable,
		statedb.RWTable[Provider].ToTable,

		// Provides the Read and ReadWrite plans table.
		NewPlansTable,
		statedb.RWTable[Plan].ToTable,

		// Provides the client to interact with Forklift resources.
		newDynamicClient,

		// Provides the k8s to tables reflector.
		newReflector,
	),

	cell.Invoke(
		// Registers the k8s to providers table reflector.
		(*Reflector).ForProviders,

		// Registers the k8s to plans table reflector.
		(*Reflector).ForPlans,
	),
)

type Config struct {
	URL             string `mapstructure:"private-networks-webhook-inventory-url"`
	CAPath          string `mapstructure:"private-networks-webhook-inventory-ca-bundle-file"`
	BearerTokenPath string `mapstructure:"private-networks-webhook-inventory-bearer-token-file"`
}

var defaultConfig = Config{
	URL: "", CAPath: "", BearerTokenPath: "",
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String("private-networks-webhook-inventory-url", def.URL,
		"The URL of the Forklift inventory service")
	flags.String("private-networks-webhook-inventory-ca-bundle-file", def.CAPath,
		"The path to the CA bundle for the Forklift inventory service")
	flags.String("private-networks-webhook-inventory-bearer-token-file", def.BearerTokenPath,
		"The path to the bearer token file to authenticate with the Forklift inventory service")
}
