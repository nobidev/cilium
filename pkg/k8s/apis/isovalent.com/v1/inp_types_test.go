// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/policy/types"
)

func TestParseTier(t *testing.T) {
	for i, tc := range []struct {
		in  intstr.IntOrString
		out types.Tier
		err bool
	}{
		{
			in:  intstr.FromInt(1),
			out: 1,
		},
		{
			in:  intstr.FromInt(2),
			out: 2,
		},
		{
			in:  intstr.FromInt(0),
			out: 255,
			err: true,
		},
		{
			in:  intstr.FromInt(254),
			out: 254,
		},
		{
			in:  intstr.FromInt(255),
			out: 255,
			err: true,
		},
		{
			in:  intstr.FromInt(256),
			out: 255,
			err: true,
		},
		{
			in:  intstr.FromInt(-1),
			out: 255,
			err: true,
		},
		{
			in:  intstr.FromString("foo"),
			out: 255,
			err: true,
		},
		{
			in:  intstr.FromString(""),
			out: types.Normal,
		},
		{
			in:  intstr.FromString("Admin"),
			out: types.Admin,
		},
		{
			in:  intstr.FromString("Normal"),
			out: types.Normal,
		},
		{
			in:  intstr.FromString("Baseline"),
			out: types.Baseline,
		},
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			r := IsovalentNetworkPolicyRule{
				Tier: &tc.in,
			}
			actual, err := r.parseTier()
			assert.Equal(t, tc.out, actual, "'%s' tier mismatch", tc.in.String())
			assert.Equal(t, tc.err, (err != nil), "%s error mismatch", tc.in.String())
		})
	}

	// test nil case
	r := IsovalentNetworkPolicyRule{}
	actual, err := r.parseTier()
	assert.Equal(t, types.Normal, actual)
	assert.NoError(t, err)
}

func TestSplitPassRule(t *testing.T) {
	noPassRule := `
endpointSelector:
  matchLabels:
    foo: baz
ingress:
  - fromEndpoints:
    - matchLabels:
        ingress: a
ingressDeny:
  - fromEndpoints:
    - matchLabels:
        ingress: d
egress:
  - toEndpoints:
    - matchLabels:
        egress: a
egressDeny:
  - toEndpoints:
    - matchLabels:
        egress: d
tier: Baseline
order: 1`

	onlyPassRule := `
endpointSelector:
  matchLabels:
    foo: baz
ingressPass:
  - fromEndpoints:
    - matchLabels:
        ingress: p
egressPass:
  - toEndpoints:
    - matchLabels:
        egress: p
tier: Baseline
order: 1`

	mixedRule := `
endpointSelector:
  matchLabels:
    foo: baz
ingress:
  - fromEndpoints:
    - matchLabels:
        ingress: a
ingressPass:
  - fromEndpoints:
    - matchLabels:
        ingress: p
ingressDeny:
  - fromEndpoints:
    - matchLabels:
        ingress: d
egress:
  - toEndpoints:
    - matchLabels:
        egress: a
egressPass:
  - toEndpoints:
    - matchLabels:
        egress: p
egressDeny:
  - toEndpoints:
    - matchLabels:
        egress: d
tier: Baseline
order: 1`

	parse := func(v string) *IsovalentNetworkPolicyRule {
		t.Helper()
		out := &IsovalentNetworkPolicyRule{}
		err := yaml.Unmarshal([]byte(v), out)
		require.NoError(t, err)
		err = out.Sanitize(false)
		require.NoError(t, err)
		return out
	}

	icnp := parse(noPassRule)
	fakeAllow, fakePass := icnp.splitPassRule()
	// If there are no pass verdicts, then just return the same rule
	assert.Equal(t, icnp, fakeAllow)
	assert.Nil(t, fakePass)

	icnp = parse(onlyPassRule)
	fakeAllow, fakePass = icnp.splitPassRule()
	assert.Nil(t, fakeAllow)
	assert.NotNil(t, fakePass)
	// orig pass should be equal to fakePass allow
	assert.Equal(t, icnp.EgressPass, fakePass.Egress)
	assert.Equal(t, icnp.IngressPass, fakePass.Ingress)
	assert.Equal(t, icnp.Tier, fakePass.Tier)
	assert.Equal(t, icnp.Order, fakePass.Order)
	assert.Equal(t, icnp.EnableDefaultDeny, fakePass.EnableDefaultDeny)

	icnp = parse(mixedRule)
	fakeAllow, fakePass = icnp.splitPassRule()
	assert.NotNil(t, fakeAllow)
	assert.NotNil(t, fakePass)
	assert.Equal(t, icnp.Egress, fakeAllow.Egress)
	assert.Equal(t, icnp.EgressDeny, fakeAllow.EgressDeny)
	assert.Equal(t, icnp.Ingress, fakeAllow.Ingress)
	assert.Equal(t, icnp.IngressDeny, fakeAllow.IngressDeny)
	assert.Equal(t, icnp.EgressPass, fakePass.Egress)
	assert.Equal(t, icnp.IngressPass, fakePass.Ingress)

	assert.Equal(t, icnp.Tier, fakeAllow.Tier)
	assert.Equal(t, icnp.Order, fakeAllow.Order)
	assert.Equal(t, icnp.EnableDefaultDeny, fakeAllow.EnableDefaultDeny)

	assert.Equal(t, icnp.Tier, fakePass.Tier)
	assert.Equal(t, icnp.Order, fakePass.Order)
	assert.Equal(t, icnp.EnableDefaultDeny, fakePass.EnableDefaultDeny)
}
