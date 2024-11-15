// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func TestConfigureAggregator(t *testing.T) {
	assert.EqualValues(t, L7NameHTTP, (&L7Flow{HTTP: &flow.HTTP{}}).Type())
	assert.EqualValues(t, L7NameKafka, (&L7Flow{Kafka: &flow.Kafka{}}).Type())
	assert.EqualValues(t, L7NameDNS, (&L7Flow{DNS: &flow.DNS{}}).Type())
	assert.EqualValues(t, L7NameUnknown, (&L7Flow{}).Type())
	var nilL7 *L7Flow
	assert.EqualValues(t, L7NameNone, nilL7.Type())
}
