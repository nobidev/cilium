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
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/hubble/parser"
)

var Cell = cell.Group(
	cell.Provide(NewPrivnetParserAdapter),
	// We replace the OSS Hubble [parser.Decoder] with an enterprise Hubble parser that wraps the OSS
	// parser, using [cell.DecorateAll].
	// For now the only enterprise related extension is the Private Network Adapter, but any future
	// enterprise extension to the Hubble parser should be added here.
	cell.DecorateAll(func(p parser.Decoder, adptr *PrivnetAdapter) (parser.Decoder, *PrivnetAdapter) {
		adptr.parser = p
		return adptr, adptr
	}),
)
