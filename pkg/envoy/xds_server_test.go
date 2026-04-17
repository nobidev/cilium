// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_type_matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	"github.com/cilium/cilium/pkg/envoy/test"
	envoyxds "github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/spanstat"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	IPv4Addr = "10.1.1.1"

	ep = &test.ProxyUpdaterMock{
		Id:   1000,
		Ipv4: "10.0.0.1",
		Ipv6: "f00d::1",
	}
)

type listenerProxyUpdaterMock struct {
	*test.ProxyUpdaterMock
	listenerProxyPorts map[string]uint16
}

func (m *listenerProxyUpdaterMock) GetListenerProxyPort(listener string) uint16 {
	return m.listenerProxyPorts[listener]
}

func (m *listenerProxyUpdaterMock) PolicyDebug(string, ...any) {}

func (m *listenerProxyUpdaterMock) IsHost() bool { return false }

func (m *listenerProxyUpdaterMock) PreviousMapState() *policy.MapState { return nil }

func (m *listenerProxyUpdaterMock) RegenerateIfAlive(*regeneration.ExternalRegenerationMetadata) <-chan bool {
	ch := make(chan bool)
	close(ch)
	return ch
}

type dummyPolicyStats struct {
	waitingForPolicyRepository spanstat.SpanStat
	policyCalculation          spanstat.SpanStat
}

func (s *dummyPolicyStats) WaitingForPolicyRepository() *spanstat.SpanStat {
	return &s.waitingForPolicyRepository
}

func (s *dummyPolicyStats) SelectorPolicyCalculation() *spanstat.SpanStat {
	return &s.policyCalculation
}

var PortRuleHTTP1 = &api.PortRuleHTTP{
	Path:    "/foo",
	Method:  "GET",
	Host:    "foo.cilium.io",
	Headers: []string{"header2: value", "header1"},
}

var PortRuleHTTP2 = &api.PortRuleHTTP{
	Path:   "/bar",
	Method: "PUT",
}

var PortRuleHTTP2HeaderMatch = &api.PortRuleHTTP{
	Path:          "/bar",
	Method:        "PUT",
	HeaderMatches: []*api.HeaderMatch{{Mismatch: api.MismatchActionReplace, Name: "user-agent", Value: "dummy-agent"}},
}

var PortRuleHTTP3 = &api.PortRuleHTTP{
	Path:   "/bar",
	Method: "GET",
}

var ExpectedHeaders1 = []*envoy_config_route.HeaderMatcher{
	{
		Name: ":authority",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
			StringMatch: &envoy_type_matcher.StringMatcher{
				MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
					SafeRegex: &envoy_type_matcher.RegexMatcher{
						Regex: "foo.cilium.io",
					},
				},
			},
		},
	},
	{
		Name: ":method",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
			StringMatch: &envoy_type_matcher.StringMatcher{
				MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
					SafeRegex: &envoy_type_matcher.RegexMatcher{
						Regex: "GET",
					},
				},
			},
		},
	},
	{
		Name: ":path",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
			StringMatch: &envoy_type_matcher.StringMatcher{
				MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
					SafeRegex: &envoy_type_matcher.RegexMatcher{
						Regex: "/foo",
					},
				},
			},
		},
	},
	{
		Name:                 "header1",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_PresentMatch{PresentMatch: true},
	},
	{
		Name: "header2",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
			StringMatch: &envoy_type_matcher.StringMatcher{
				MatchPattern: &envoy_type_matcher.StringMatcher_Exact{
					Exact: "value",
				},
			},
		},
	},
}

var ExpectedHeaders2 = []*envoy_config_route.HeaderMatcher{
	{
		Name: ":method",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
			StringMatch: &envoy_type_matcher.StringMatcher{
				MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
					SafeRegex: &envoy_type_matcher.RegexMatcher{
						Regex: "PUT",
					},
				},
			},
		},
	},
	{
		Name: ":path",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
			StringMatch: &envoy_type_matcher.StringMatcher{
				MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
					SafeRegex: &envoy_type_matcher.RegexMatcher{
						Regex: "/bar",
					},
				},
			},
		},
	},
}

var ExpectedHeaderMatches2 = []*cilium.HeaderMatch{
	{
		MismatchAction: cilium.HeaderMatch_REPLACE_ON_MISMATCH,
		Name:           "user-agent",
		Value:          "dummy-agent",
	},
}

var ExpectedHeaders3 = []*envoy_config_route.HeaderMatcher{
	{
		Name: ":method",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
			StringMatch: &envoy_type_matcher.StringMatcher{
				MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
					SafeRegex: &envoy_type_matcher.RegexMatcher{
						Regex: "GET",
					},
				},
			},
		},
	},
	{
		Name: ":path",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
			StringMatch: &envoy_type_matcher.StringMatcher{
				MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
					SafeRegex: &envoy_type_matcher.RegexMatcher{
						Regex: "/bar",
					},
				},
			},
		},
	},
}

var (
	dummySelectorCacheUser = &testpolicy.DummySelectorCacheUser{}

	IdentityCache = identity.IdentityMap{
		1001: labels.LabelArray{
			labels.NewLabel("app", "etcd", labels.LabelSourceK8s),
			labels.NewLabel("version", "v1", labels.LabelSourceK8s),
		},
		1002: labels.LabelArray{
			labels.NewLabel("app", "etcd", labels.LabelSourceK8s),
			labels.NewLabel("version", "v2", labels.LabelSourceK8s),
		},
		1003: labels.LabelArray{
			labels.NewLabel("app", "cassandra", labels.LabelSourceK8s),
			labels.NewLabel("version", "v1", labels.LabelSourceK8s),
		},
	}
	// slogloggercheck: the default logger is enough for tests.
	testSelectorCache = policy.NewSelectorCache(logging.DefaultSlogLogger, IdentityCache)

	wildcardCachedSelector, _ = testSelectorCache.AddIdentitySelectorForTest(dummySelectorCacheUser, api.WildcardEndpointSelector)

	EndpointSelector1 = api.NewESFromLabels(
		labels.NewLabel("app", "etcd", labels.LabelSourceK8s),
	)
	cachedSelector1, _ = testSelectorCache.AddIdentitySelectorForTest(dummySelectorCacheUser, EndpointSelector1)

	// EndpointSelector1 with FromRequires("k8s:version=v2") folded in
	RequiresV2Selector1 = api.NewESFromLabels(
		labels.NewLabel("app", "etcd", labels.LabelSourceK8s),
		labels.NewLabel("version", "v2", labels.LabelSourceK8s),
	)
	cachedRequiresV2Selector1, _ = testSelectorCache.AddIdentitySelectorForTest(dummySelectorCacheUser, RequiresV2Selector1)

	EndpointSelector2 = api.NewESFromLabels(
		labels.NewLabel("version", "v1", labels.LabelSourceK8s),
	)
	cachedSelector2, _ = testSelectorCache.AddIdentitySelectorForTest(dummySelectorCacheUser, EndpointSelector2)
)

var L7Rules12 = &policy.PerSelectorPolicy{
	L7Parser: policy.ParserTypeHTTP,
	L7Rules:  api.L7Rules{HTTP: []api.PortRuleHTTP{*PortRuleHTTP1, *PortRuleHTTP2}},
}

var denyPerSelectorPolicy = &policy.PerSelectorPolicy{Verdict: types.Deny}

var L7Rules12Deny = &policy.PerSelectorPolicy{
	Verdict:  types.Deny,
	L7Parser: policy.ParserTypeHTTP,
	L7Rules:  api.L7Rules{HTTP: []api.PortRuleHTTP{*PortRuleHTTP1, *PortRuleHTTP2}},
}

var L7Rules12HeaderMatch = &policy.PerSelectorPolicy{
	L7Parser: policy.ParserTypeHTTP,
	L7Rules:  api.L7Rules{HTTP: []api.PortRuleHTTP{*PortRuleHTTP1, *PortRuleHTTP2HeaderMatch}},
}

var L7Rules1 = &policy.PerSelectorPolicy{
	L7Parser: policy.ParserTypeHTTP,
	L7Rules:  api.L7Rules{HTTP: []api.PortRuleHTTP{*PortRuleHTTP1}},
}

var ExpectedHttpRule1 = &cilium.PortNetworkPolicyRule_HttpRules{
	HttpRules: &cilium.HttpNetworkPolicyRules{
		HttpRules: []*cilium.HttpNetworkPolicyRule{
			{Headers: ExpectedHeaders1},
		},
	},
}

var ExpectedHttpRule12 = &cilium.PortNetworkPolicyRule_HttpRules{
	HttpRules: &cilium.HttpNetworkPolicyRules{
		HttpRules: []*cilium.HttpNetworkPolicyRule{
			{Headers: ExpectedHeaders2},
			{Headers: ExpectedHeaders1},
		},
	},
}

var ExpectedHttpRule122HeaderMatch = &cilium.PortNetworkPolicyRule_HttpRules{
	HttpRules: &cilium.HttpNetworkPolicyRules{
		HttpRules: []*cilium.HttpNetworkPolicyRule{
			{Headers: ExpectedHeaders2, HeaderMatches: ExpectedHeaderMatches2},
			{Headers: ExpectedHeaders1},
		},
	},
}

var ExpectedPortNetworkPolicyRule12 = &cilium.PortNetworkPolicyRule{
	Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
	RemotePolicies: []uint32{1001, 1002},
	L7:             ExpectedHttpRule12,
}

var ExpectedSelectorPortNetworkPolicyRule12 = &cilium.PortNetworkPolicyRule{
	Precedence: uint32(policyTypes.MaxAllowPrecedence + 1),
	Selectors:  []string{"s-2"},
	L7:         ExpectedHttpRule12,
}

var ExpectedPortNetworkPolicyRule12Precedence = &cilium.PortNetworkPolicyRule{
	Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
	RemotePolicies: []uint32{1001, 1002},
	L7:             ExpectedHttpRule12,
}

var ExpectedSelectorPortNetworkPolicyRule12Precedence = &cilium.PortNetworkPolicyRule{
	Precedence: uint32(policyTypes.MaxAllowPrecedence + 1),
	Selectors:  []string{"s-2"},
	L7:         ExpectedHttpRule12,
}

var ExpectedPortNetworkPolicyRule12Deny = &cilium.PortNetworkPolicyRule{
	Precedence:     uint32(policyTypes.MaxDenyPrecedence),
	Verdict:        DenyVerdict,
	RemotePolicies: []uint32{1001, 1002},
}

var ExpectedSelectorPortNetworkPolicyRule12Deny = &cilium.PortNetworkPolicyRule{
	Precedence: uint32(policyTypes.MaxDenyPrecedence),
	Verdict:    DenyVerdict,
	Selectors:  []string{"s-2"},
}

var ExpectedPortNetworkPolicyRule12DenyPrecedence = &cilium.PortNetworkPolicyRule{
	Verdict:        DenyVerdict,
	RemotePolicies: []uint32{1001, 1002},
	Precedence:     uint32(policyTypes.MaxDenyPrecedence),
}

var ExpectedSelectorPortNetworkPolicyRule12DenyPrecedence = &cilium.PortNetworkPolicyRule{
	Verdict:    DenyVerdict,
	Selectors:  []string{"s-2"},
	Precedence: uint32(policyTypes.MaxDenyPrecedence),
}

var ExpectedPortNetworkPolicyRule12Wildcard = &cilium.PortNetworkPolicyRule{
	Precedence: uint32(policyTypes.MaxAllowPrecedence + 1),
	L7:         ExpectedHttpRule12,
}

var ExpectedPortNetworkPolicyRule122HeaderMatch = &cilium.PortNetworkPolicyRule{
	Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
	RemotePolicies: []uint32{1001, 1002},
	L7:             ExpectedHttpRule122HeaderMatch,
}

var ExpectedSelectorPortNetworkPolicyRule122HeaderMatch = &cilium.PortNetworkPolicyRule{
	Precedence: uint32(policyTypes.MaxAllowPrecedence + 1),
	Selectors:  []string{"s-2"},
	L7:         ExpectedHttpRule122HeaderMatch,
}

var ExpectedPortNetworkPolicyRule122HeaderMatchPrecedence = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint32{1001, 1002},
	L7:             ExpectedHttpRule122HeaderMatch,
	Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
}

var ExpectedSelectorPortNetworkPolicyRule122HeaderMatchPrecedence = &cilium.PortNetworkPolicyRule{
	Selectors:  []string{"s-2"},
	L7:         ExpectedHttpRule122HeaderMatch,
	Precedence: uint32(policyTypes.MaxAllowPrecedence + 1),
}

var ExpectedPortNetworkPolicyRule1 = &cilium.PortNetworkPolicyRule{
	Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
	RemotePolicies: []uint32{1001, 1003},
	L7:             ExpectedHttpRule1,
}

var ExpectedSelectorPortNetworkPolicyRule1 = &cilium.PortNetworkPolicyRule{
	Precedence: uint32(policyTypes.MaxAllowPrecedence + 1),
	Selectors:  []string{"s-4"},
	L7:         ExpectedHttpRule1,
}

var ExpectedPortNetworkPolicyRule1Precedence = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint32{1001, 1003},
	L7:             ExpectedHttpRule1,
	Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
}

var ExpectedSelectorPortNetworkPolicyRule1Precedence = &cilium.PortNetworkPolicyRule{
	Selectors:  []string{"s-4"},
	L7:         ExpectedHttpRule1,
	Precedence: uint32(policyTypes.MaxAllowPrecedence + 1),
}

var ExpectedPortNetworkPolicyRule1Wildcard = &cilium.PortNetworkPolicyRule{
	L7: ExpectedHttpRule1,
}

var L4PolicyMap1 = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
		PerSelectorPolicies: policy.L7DataMap{
			cachedSelector1: L7Rules12,
		},
	},
})

var L4PolicyMap1HeaderMatch = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
		PerSelectorPolicies: policy.L7DataMap{
			cachedSelector1: L7Rules12HeaderMatch,
		},
	},
})

var L4PolicyMap1RequiresV2 = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
		PerSelectorPolicies: policy.L7DataMap{
			cachedSelector1:           L7Rules1,
			cachedRequiresV2Selector1: L7Rules12,
		},
	},
})

var L4PolicyMap2 = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"8080/TCP": {
		Port:     8080,
		Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
		PerSelectorPolicies: policy.L7DataMap{
			cachedSelector2: L7Rules1,
		},
	},
})

var L4PolicyMap1Deny2 = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"8080/TCP": {
		Port:     8080,
		Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
		PerSelectorPolicies: policy.L7DataMap{
			cachedSelector1: denyPerSelectorPolicy,
			cachedSelector2: L7Rules1,
		},
	},
})

var L4PolicyMap3 = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
		PerSelectorPolicies: policy.L7DataMap{
			wildcardCachedSelector: L7Rules12,
		},
	},
})

// L4PolicyMap4 is an L4-only policy, with no L7 rules.
var L4PolicyMap4 = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
		PerSelectorPolicies: policy.L7DataMap{
			cachedSelector1: &policy.PerSelectorPolicy{L7Rules: api.L7Rules{}},
		},
	},
})

// L4PolicyMap5 is an L4-only policy, with no L7 rules.
var L4PolicyMap5 = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
		PerSelectorPolicies: policy.L7DataMap{
			wildcardCachedSelector: &policy.PerSelectorPolicy{L7Rules: api.L7Rules{}},
		},
	},
})

// L4PolicyMap5 is an L4-only policy, with no L7 rules.
var L4PolicyMap5LowestPriority = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
		PerSelectorPolicies: policy.L7DataMap{
			wildcardCachedSelector: &policy.PerSelectorPolicy{
				Priority: policyTypes.LowestPriority,
				L7Rules:  api.L7Rules{},
			},
		},
	},
})

// L4PolicyMapSNI is an L4-only policy, with SNI enforcement
var L4PolicyMapSNI = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"443/TCP": {
		Port:     443,
		Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
		PerSelectorPolicies: policy.L7DataMap{
			wildcardCachedSelector: &policy.PerSelectorPolicy{
				ServerNames: policy.NewStringSet([]string{
					"jarno.cilium.rocks",
					"ab.cd.com",
				}),
			},
		},
	},
})

var ExpectedPerPortPoliciesSNI = []*cilium.PortNetworkPolicy{
	{
		Port:     443,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			{
				Precedence:  uint32(policyTypes.MaxAllowPrecedence),
				ServerNames: []string{"ab.cd.com", "jarno.cilium.rocks"},
			},
		},
	},
}

// L4PassPolicy is a policy with a pass verdict
var L4PassPolicy = &policy.L4Policy{
	Ingress: policy.NewL4DirectionPolicyForTest(L4PolicyMapPass,
		[]types.Priority{0, 0x2000}),
}

var L4PolicyMapPass = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"0/TCP": {
		Tier:     0,
		Port:     0,
		Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
		PerSelectorPolicies: policy.L7DataMap{
			cachedSelector1: &policy.PerSelectorPolicy{
				Priority: 0,
				Verdict:  policyTypes.Pass,
			},
			wildcardCachedSelector: &policy.PerSelectorPolicy{
				Priority: 40,
				Verdict:  policyTypes.Deny,
			},
		},
	},
	"443/TCP": {
		Tier:     1,
		Port:     443,
		Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
		PerSelectorPolicies: policy.L7DataMap{
			cachedSelector1: &policy.PerSelectorPolicy{
				Priority: 50,
			},
		},
	},
})

var ExpectedPerPortPoliciesPass = []*cilium.PortNetworkPolicy{
	{
		Port:     0,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			{
				Verdict: &cilium.PortNetworkPolicyRule_PassPrecedence{
					PassPrecedence: 0xffe00000,
				},
				RemotePolicies: []uint32{1001, 1002},
				Precedence:     0xffffff00,
			},
			{
				Verdict:    DenyVerdict,
				Precedence: 0xffffd7ff, // ~40
			},
		},
	},
	{
		Port:     443,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			{
				RemotePolicies: []uint32{1001, 1002},
				Precedence:     0xffffcd01, // ~50
			},
		},
	},
}

var ExpectedPerPortPolicies1 = []*cilium.PortNetworkPolicy{
	{
		Port:     8080,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule1,
		},
	},
}

var ExpectedPerPortPolicies1Deny2 = []*cilium.PortNetworkPolicy{
	{
		Port:     8080,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule12Deny,
			ExpectedPortNetworkPolicyRule1,
		},
	},
}

var ExpectedPerPortPolicies1Wildcard = []*cilium.PortNetworkPolicy{
	{
		Port:     8080,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule1Wildcard,
		},
	},
}

var ExpectedPerPortPolicies122HeaderMatch = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule122HeaderMatch,
		},
	},
}

var ExpectedPerPortPolicies12 = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule12,
		},
	},
}

var ExpectedPerPortPolicies12Wildcard = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule12Wildcard,
		},
	},
}

var ExpectedPerPortPolicies12RequiresV2 = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
			RemotePolicies: []uint32{1001, 1002},
			L7:             ExpectedHttpRule1,
		}, {
			Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
			RemotePolicies: []uint32{1002},
			L7:             ExpectedHttpRule12,
		}},
	},
}

var ExpectedPerPortPolicies = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			Precedence:     uint32(policyTypes.MaxAllowPrecedence),
			RemotePolicies: []uint32{1001, 1002},
		}},
	},
}

var ExpectedPerPortPoliciesWildcard = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			Precedence: uint32(policyTypes.MaxAllowPrecedence),
		}},
	},
}

var L4Deny2Policy1 = &policy.L4Policy{
	Ingress: policy.L4DirectionPolicy{PortRules: L4PolicyMap1Deny2},
}

var L4Policy4 = &policy.L4Policy{
	Ingress: policy.L4DirectionPolicy{PortRules: L4PolicyMap4},
}

var L4Policy5 = &policy.L4Policy{
	Ingress: policy.L4DirectionPolicy{PortRules: L4PolicyMap5},
}

var L4HeaderMatchPolicy1 = &policy.L4Policy{
	Ingress: policy.L4DirectionPolicy{PortRules: L4PolicyMap1HeaderMatch},
}

var L4SNIPolicy = &policy.L4Policy{
	Ingress: policy.L4DirectionPolicy{PortRules: L4PolicyMapSNI},
}

var L4Policy1 = &policy.L4Policy{
	Ingress: policy.L4DirectionPolicy{PortRules: L4PolicyMap1},
	Egress:  policy.L4DirectionPolicy{PortRules: L4PolicyMap2},
}

var L4Policy1RequiresV2 = &policy.L4Policy{
	Ingress: policy.L4DirectionPolicy{PortRules: L4PolicyMap1RequiresV2},
	Egress:  policy.L4DirectionPolicy{PortRules: L4PolicyMap2},
}

var L4Policy2 = &policy.L4Policy{
	Ingress: policy.L4DirectionPolicy{PortRules: L4PolicyMap3},
	Egress:  policy.L4DirectionPolicy{PortRules: L4PolicyMap2},
}

var PortRuleHeaderMatchSecret = &api.PortRuleHTTP{
	HeaderMatches: []*api.HeaderMatch{
		{
			Mismatch: "",
			Name:     "VeryImportantHeader",
			Secret: &api.Secret{
				Name:      "secretName",
				Namespace: "cilium-secrets",
			},
		},
	},
}

var PortRuleHeaderMatchSecretLogOnMismatch = &api.PortRuleHTTP{
	HeaderMatches: []*api.HeaderMatch{
		{
			Mismatch: api.MismatchActionLog,
			Name:     "VeryImportantHeader",
			Secret: &api.Secret{
				Name:      "secretName",
				Namespace: "cilium-secrets",
			},
		},
	},
}

func Test_getWildcardNetworkPolicyRules(t *testing.T) {
	xds := testXdsServer(t)
	version := testSelectorCache.GetSelectorSnapshot()

	t.Run("allow_wildcard_and_specific_rules", func(t *testing.T) {
		perSelectorPoliciesWithWildcard := policy.L7DataMap{
			cachedSelector1:           nil,
			cachedRequiresV2Selector1: nil,
			wildcardCachedSelector:    nil,
		}

		referredSelectors := make(SelectorSet)
		obtained, isPass, wildcardSelectorPrecedence := xds.getWildcardPortNetworkPolicyRules(ep, version, policyTypes.HighestPriority, policyTypes.LowestPriority, perSelectorPoliciesWithWildcard, false, false, "", referredSelectors)
		obtained = projectLegacyPortPoliciesForTest(t, xds, version, uint64(ep.GetID()), ingressDirection, []*cilium.PortNetworkPolicy{{
			Port:     0,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules:    obtained,
		}}, referredSelectors)[0].GetRules()
		require.EqualExportedValues(t, []*cilium.PortNetworkPolicyRule{{
			Precedence: uint32(policyTypes.MaxAllowPrecedence),
		}}, obtained)
		require.False(t, isPass)
		require.NotZero(t, wildcardSelectorPrecedence)
		require.True(t, wildcardSelectorPrecedence.IsAllow())
	})

	t.Run("non_wildcard_allow_and_deny_rules_are_grouped", func(t *testing.T) {
		// both cachedSelector2 and cachedSelector2 select identity 1001, but duplicates must have been removed
		perSelectorPolicies := policy.L7DataMap{
			cachedSelector2:           nil,
			cachedSelector1:           denyPerSelectorPolicy,
			cachedRequiresV2Selector1: nil,
		}

		referredSelectors := make(SelectorSet)
		obtained, isPass, wildcardSelectorPrecedence := xds.getWildcardPortNetworkPolicyRules(ep, version, policyTypes.HighestPriority, policyTypes.LowestPriority, perSelectorPolicies, false, false, "", referredSelectors)
		obtained = projectLegacyPortPoliciesForTest(t, xds, version, uint64(ep.GetID()), ingressDirection, []*cilium.PortNetworkPolicy{{
			Port:     0,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules:    obtained,
		}}, referredSelectors)[0].GetRules()
		require.EqualExportedValues(t, []*cilium.PortNetworkPolicyRule{{
			Precedence:     uint32(policyTypes.MaxDenyPrecedence),
			Verdict:        DenyVerdict,
			RemotePolicies: []uint32{1001, 1002},
		}, {
			Precedence:     uint32(policyTypes.MaxAllowPrecedence),
			RemotePolicies: []uint32{1001, 1002, 1003},
		}}, obtained)
		require.False(t, isPass)
		require.Zero(t, wildcardSelectorPrecedence)
	})

	t.Run("single_selector_wildcard_pass_sets_have_pass_and_precedence", func(t *testing.T) {
		passPriority := policyTypes.Priority(7)
		passPolicy := &policy.PerSelectorPolicy{
			Priority: passPriority,
			Verdict:  types.Pass,
		}

		referredSelectors := make(SelectorSet)
		obtained, isPass, wildcardSelectorPrecedence := xds.getWildcardPortNetworkPolicyRules(ep, version, policyTypes.HighestPriority, policyTypes.LowestPriority, policy.L7DataMap{
			wildcardCachedSelector: passPolicy,
		}, false, false, "", referredSelectors)
		obtained = projectLegacyPortPoliciesForTest(t, xds, version, uint64(ep.GetID()), ingressDirection, []*cilium.PortNetworkPolicy{{
			Port:     0,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules:    obtained,
		}}, referredSelectors)[0].GetRules()

		require.EqualExportedValues(t, []*cilium.PortNetworkPolicyRule{{
			Precedence: uint32(passPriority.ToPassPrecedence()),
			Verdict: &cilium.PortNetworkPolicyRule_PassPrecedence{
				PassPrecedence: uint32(policyTypes.LowestPriority.ToPassPrecedence()),
			},
		}}, obtained)
		require.True(t, isPass)
		require.Equal(t, passPriority.ToPassPrecedence(), wildcardSelectorPrecedence)
		require.True(t, wildcardSelectorPrecedence.IsPass())
	})

	t.Run("grouped_wildcard_pass_keeps_same_priority_allow_and_deny", func(t *testing.T) {
		passPriority := policyTypes.Priority(9)
		allowPriority := passPriority
		denyPriority := passPriority

		referredSelectors := make(SelectorSet)
		obtained, isPass, wildcardSelectorPrecedence := xds.getWildcardPortNetworkPolicyRules(ep, version, policyTypes.HighestPriority, policyTypes.LowestPriority, policy.L7DataMap{
			wildcardCachedSelector: {
				Priority: passPriority,
				Verdict:  types.Pass,
			},
			cachedSelector1: {
				Priority: allowPriority,
			},
			cachedSelector2: {
				Priority: denyPriority,
				Verdict:  types.Deny,
			},
		}, false, false, "", referredSelectors)
		obtained = projectLegacyPortPoliciesForTest(t, xds, version, uint64(ep.GetID()), ingressDirection, []*cilium.PortNetworkPolicy{{
			Port:     0,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules:    obtained,
		}}, referredSelectors)[0].GetRules()

		require.True(t, isPass)
		require.Equal(t, passPriority.ToPassPrecedence(), wildcardSelectorPrecedence)
		expected := []*cilium.PortNetworkPolicyRule{{
			Precedence: uint32(passPriority.ToPassPrecedence()),
			Verdict: &cilium.PortNetworkPolicyRule_PassPrecedence{
				PassPrecedence: uint32(policyTypes.LowestPriority.ToPassPrecedence()),
			},
		}, {
			Precedence:     uint32(allowPriority.ToAllowPrecedence()),
			RemotePolicies: []uint32{1001, 1002},
		}, {
			Precedence:     uint32(denyPriority.ToDenyPrecedence()),
			Verdict:        DenyVerdict,
			RemotePolicies: []uint32{1001, 1003},
		}}
		envoypolicy.SortPortNetworkPolicyRules(expected)
		envoypolicy.SortPortNetworkPolicyRules(obtained)
		require.EqualExportedValues(t, expected, obtained)
	})

	t.Run("grouped_non_wildcard_pass_with_empty_selection_is_skipped", func(t *testing.T) {
		noneCachedSelector, _ := testSelectorCache.AddIdentitySelectorForTest(dummySelectorCacheUser, api.EndpointSelectorNone)

		referredSelectors := make(SelectorSet)
		obtained, isPass, wildcardSelectorPrecedence := xds.getWildcardPortNetworkPolicyRules(ep, version, policyTypes.HighestPriority, policyTypes.LowestPriority, policy.L7DataMap{
			cachedSelector1: {
				Priority: policyTypes.Priority(3),
			},
			noneCachedSelector: {
				Priority: policyTypes.Priority(2),
				Verdict:  types.Pass,
			},
		}, false, false, "", referredSelectors)
		obtained = projectLegacyPortPoliciesForTest(t, xds, version, uint64(ep.GetID()), ingressDirection, []*cilium.PortNetworkPolicy{{
			Port:     0,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules:    obtained,
		}}, referredSelectors)[0].GetRules()

		require.EqualExportedValues(t, []*cilium.PortNetworkPolicyRule{{
			Precedence:     uint32(policyTypes.Priority(3).ToAllowPrecedence()),
			RemotePolicies: []uint32{1001, 1002},
		}}, obtained)
		require.True(t, isPass)
		require.Zero(t, wildcardSelectorPrecedence)
	})
}

func TestGetPortNetworkPolicyRule(t *testing.T) {
	xds := testXdsServer(t)

	version := testSelectorCache.GetSelectorSnapshot()

	referredSelectors := make(SelectorSet)
	obtained, canShortCircuit := xds.getPortNetworkPolicyRule(ep, version, cachedSelector1, L7Rules12, policyTypes.LowestPriority, policyTypes.LowestPriority, false, false, "", referredSelectors)
	obtained = projectLegacyRuleForTest(t, xds, version, uint64(ep.GetID()), ingressDirection, 0, obtained, referredSelectors)
	require.EqualExportedValues(t, ExpectedPortNetworkPolicyRule12, obtained)
	require.True(t, canShortCircuit)

	referredSelectors = make(SelectorSet)
	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector1, L7Rules12Deny, policyTypes.LowestPriority, policyTypes.LowestPriority, false, false, "", referredSelectors)
	obtained = projectLegacyRuleForTest(t, xds, version, uint64(ep.GetID()), ingressDirection, 0, obtained, referredSelectors)
	require.EqualExportedValues(t, ExpectedPortNetworkPolicyRule12Deny, obtained)
	require.False(t, canShortCircuit)

	referredSelectors = make(SelectorSet)
	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector1, L7Rules12HeaderMatch, policyTypes.LowestPriority, policyTypes.LowestPriority, false, false, "", referredSelectors)
	obtained = projectLegacyRuleForTest(t, xds, version, uint64(ep.GetID()), ingressDirection, 0, obtained, referredSelectors)
	require.EqualExportedValues(t, ExpectedPortNetworkPolicyRule122HeaderMatch, obtained)
	require.False(t, canShortCircuit)

	referredSelectors = make(SelectorSet)
	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector2, L7Rules1, policyTypes.LowestPriority, policyTypes.LowestPriority, false, false, "", referredSelectors)
	obtained = projectLegacyRuleForTest(t, xds, version, uint64(ep.GetID()), ingressDirection, 0, obtained, referredSelectors)
	require.EqualExportedValues(t, ExpectedPortNetworkPolicyRule1, obtained)
	require.True(t, canShortCircuit)

	// With precedence

	referredSelectors = make(SelectorSet)
	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector1, L7Rules12, policyTypes.HighestPriority, policyTypes.LowestPriority, false, false, "", referredSelectors)
	obtained = projectLegacyRuleForTest(t, xds, version, uint64(ep.GetID()), ingressDirection, 0, obtained, referredSelectors)
	require.EqualExportedValues(t, ExpectedPortNetworkPolicyRule12Precedence, obtained)
	require.True(t, canShortCircuit)

	referredSelectors = make(SelectorSet)
	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector1, L7Rules12Deny, policyTypes.HighestPriority, policyTypes.LowestPriority, false, false, "", referredSelectors)
	obtained = projectLegacyRuleForTest(t, xds, version, uint64(ep.GetID()), ingressDirection, 0, obtained, referredSelectors)
	require.EqualExportedValues(t, ExpectedPortNetworkPolicyRule12DenyPrecedence, obtained)
	require.False(t, canShortCircuit)

	referredSelectors = make(SelectorSet)
	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector1, L7Rules12HeaderMatch, policyTypes.HighestPriority, policyTypes.LowestPriority, false, false, "", referredSelectors)
	obtained = projectLegacyRuleForTest(t, xds, version, uint64(ep.GetID()), ingressDirection, 0, obtained, referredSelectors)
	require.EqualExportedValues(t, ExpectedPortNetworkPolicyRule122HeaderMatchPrecedence, obtained)
	require.False(t, canShortCircuit)

	referredSelectors = make(SelectorSet)
	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector2, L7Rules1, policyTypes.HighestPriority, policyTypes.LowestPriority, false, false, "", referredSelectors)
	obtained = projectLegacyRuleForTest(t, xds, version, uint64(ep.GetID()), ingressDirection, 0, obtained, referredSelectors)
	require.EqualExportedValues(t, ExpectedPortNetworkPolicyRule1Precedence, obtained)
	require.True(t, canShortCircuit)

	// with pass verdict

	referredSelectors = make(SelectorSet)
	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector1,
		&policy.PerSelectorPolicy{Verdict: types.Pass, Priority: 0xffff},
		0xffff, 0x1ffff, false, false, "", referredSelectors)
	obtained = projectLegacyRuleForTest(t, xds, version, uint64(ep.GetID()), ingressDirection, 0, obtained, referredSelectors)
	require.EqualExportedValues(t, &cilium.PortNetworkPolicyRule{
		Precedence:     0xff000000,
		Verdict:        &cilium.PortNetworkPolicyRule_PassPrecedence{PassPrecedence: 0xfe000000},
		RemotePolicies: []uint32{1001, 1002},
	}, obtained)
	require.True(t, canShortCircuit)
}

func TestGetPortNetworkPolicyRule_Selectors(t *testing.T) {
	xds := testDeltaXdsServer(t)

	version := testSelectorCache.GetSelectorSnapshot()

	obtained, canShortCircuit := xds.getPortNetworkPolicyRule(ep, version, cachedSelector1, L7Rules12, policyTypes.LowestPriority, policyTypes.LowestPriority, false, false, "", nil)
	require.Equal(t, ExpectedSelectorPortNetworkPolicyRule12, obtained)
	require.True(t, canShortCircuit)

	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector1, L7Rules12Deny, policyTypes.LowestPriority, policyTypes.LowestPriority, false, false, "", nil)
	require.Equal(t, ExpectedSelectorPortNetworkPolicyRule12Deny, obtained)
	require.False(t, canShortCircuit)

	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector1, L7Rules12HeaderMatch, policyTypes.LowestPriority, policyTypes.LowestPriority, false, false, "", nil)
	require.Equal(t, ExpectedSelectorPortNetworkPolicyRule122HeaderMatch, obtained)
	require.False(t, canShortCircuit)

	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector2, L7Rules1, policyTypes.LowestPriority, policyTypes.LowestPriority, false, false, "", nil)
	require.Equal(t, ExpectedSelectorPortNetworkPolicyRule1, obtained)
	require.True(t, canShortCircuit)

	// With precedence

	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector1, L7Rules12, policyTypes.HighestPriority, policyTypes.LowestPriority, false, false, "", nil)
	require.Equal(t, ExpectedSelectorPortNetworkPolicyRule12Precedence, obtained)
	require.True(t, canShortCircuit)

	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector1, L7Rules12Deny, policyTypes.HighestPriority, policyTypes.LowestPriority, false, false, "", nil)
	require.Equal(t, ExpectedSelectorPortNetworkPolicyRule12DenyPrecedence, obtained)
	require.False(t, canShortCircuit)

	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector1, L7Rules12HeaderMatch, policyTypes.HighestPriority, policyTypes.LowestPriority, false, false, "", nil)
	require.Equal(t, ExpectedSelectorPortNetworkPolicyRule122HeaderMatchPrecedence, obtained)
	require.False(t, canShortCircuit)

	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector2, L7Rules1, policyTypes.HighestPriority, policyTypes.LowestPriority, false, false, "", nil)
	require.Equal(t, ExpectedSelectorPortNetworkPolicyRule1Precedence, obtained)
	require.True(t, canShortCircuit)

	// with pass verdict

	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector1,
		&policy.PerSelectorPolicy{Verdict: types.Pass, Priority: 0xffff},
		0xffff, 0x1ffff, false, false, "", nil)
	require.Equal(t, &cilium.PortNetworkPolicyRule{
		Precedence: 0xff000000,
		Verdict:    &cilium.PortNetworkPolicyRule_PassPrecedence{PassPrecedence: 0xfe000000},
		Selectors:  []string{"s-2"},
	}, obtained)
	require.True(t, canShortCircuit)
}

func TestGetDirectionNetworkPolicy(t *testing.T) {
	// L4+L7
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()
	referredSelectors := make(SelectorSet)
	obtained := xds.getDirectionNetworkPolicy(ep, selectors, &L4Policy1.Ingress, true, false, false, "ingress", "", referredSelectors)
	obtained = projectLegacyPortPoliciesForTest(t, xds, selectors, uint64(ep.GetID()), ingressDirection, obtained, referredSelectors)
	require.EqualExportedValues(t, ExpectedPerPortPolicies12, obtained)

	// L4+L7 with header mods
	referredSelectors = make(SelectorSet)
	obtained = xds.getDirectionNetworkPolicy(ep, selectors, &L4HeaderMatchPolicy1.Ingress, true, false, false, "ingress", "", referredSelectors)
	obtained = projectLegacyPortPoliciesForTest(t, xds, selectors, uint64(ep.GetID()), ingressDirection, obtained, referredSelectors)
	require.EqualExportedValues(t, ExpectedPerPortPolicies122HeaderMatch, obtained)

	// L4+L7
	referredSelectors = make(SelectorSet)
	obtained = xds.getDirectionNetworkPolicy(ep, selectors, &L4Policy1.Egress, true, false, false, "egress", "", referredSelectors)
	obtained = projectLegacyPortPoliciesForTest(t, xds, selectors, uint64(ep.GetID()), egressDirection, obtained, referredSelectors)
	require.EqualExportedValues(t, ExpectedPerPortPolicies1, obtained)

	// L4+L7 with Deny L3
	referredSelectors = make(SelectorSet)
	obtained = xds.getDirectionNetworkPolicy(ep, selectors, &L4Deny2Policy1.Ingress, true, false, false, "ingress", "", referredSelectors)
	obtained = projectLegacyPortPoliciesForTest(t, xds, selectors, uint64(ep.GetID()), ingressDirection, obtained, referredSelectors)
	require.EqualExportedValues(t, ExpectedPerPortPolicies1Deny2, obtained)

	// L4-only
	referredSelectors = make(SelectorSet)
	obtained = xds.getDirectionNetworkPolicy(ep, selectors, &L4Policy4.Ingress, true, false, false, "ingress", "", referredSelectors)
	obtained = projectLegacyPortPoliciesForTest(t, xds, selectors, uint64(ep.GetID()), ingressDirection, obtained, referredSelectors)
	require.EqualExportedValues(t, ExpectedPerPortPolicies, obtained)

	// L4-only
	referredSelectors = make(SelectorSet)
	obtained = xds.getDirectionNetworkPolicy(ep, selectors, &L4Policy5.Ingress, true, false, false, "ingress", "", referredSelectors)
	obtained = projectLegacyPortPoliciesForTest(t, xds, selectors, uint64(ep.GetID()), ingressDirection, obtained, referredSelectors)
	require.EqualExportedValues(t, ExpectedPerPortPoliciesWildcard, obtained)

	// L4-only with SNI
	referredSelectors = make(SelectorSet)
	obtained = xds.getDirectionNetworkPolicy(ep, selectors, &L4SNIPolicy.Ingress, true, false, false, "ingress", "", referredSelectors)
	obtained = projectLegacyPortPoliciesForTest(t, xds, selectors, uint64(ep.GetID()), ingressDirection, obtained, referredSelectors)
	require.EqualExportedValues(t, ExpectedPerPortPoliciesSNI, obtained)

	// with pass verdict
	referredSelectors = make(SelectorSet)
	obtained = xds.getDirectionNetworkPolicy(ep, selectors, &L4PassPolicy.Ingress, true, false, false, "ingress", "", referredSelectors)
	obtained = projectLegacyPortPoliciesForTest(t, xds, selectors, uint64(ep.GetID()), ingressDirection, obtained, referredSelectors)
	require.EqualExportedValues(t, ExpectedPerPortPoliciesPass, obtained)

}

func TestGetDirectionNetworkPolicyWildcardPass(t *testing.T) {
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()

	t.Run("wildcard_pass_does_not_short_circuit_later_tiers", func(t *testing.T) {
		l4DirectionPolicy := &policy.L4DirectionPolicy{}
		*l4DirectionPolicy = policy.NewL4DirectionPolicyForTest(policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
			"0/TCP": {
				Tier:     0,
				Port:     0,
				Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
				PerSelectorPolicies: policy.L7DataMap{
					wildcardCachedSelector: {
						Priority: policyTypes.HighestPriority,
						Verdict:  types.Pass,
					},
				},
			},
			"443/TCP": {
				Tier:     1,
				Port:     443,
				Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
				PerSelectorPolicies: policy.L7DataMap{
					cachedSelector1: {
						Priority: policyTypes.Priority(0x100),
					},
				},
			},
		}), []types.Priority{0, 0x100})

		referredSelectors := make(SelectorSet)
		obtained := xds.getDirectionNetworkPolicy(ep, selectors, l4DirectionPolicy, true, false, false, "ingress", "", referredSelectors)
		obtained = projectLegacyPortPoliciesForTest(t, xds, selectors, uint64(ep.GetID()), ingressDirection, obtained, referredSelectors)
		require.EqualExportedValues(t, []*cilium.PortNetworkPolicy{{
			Port:     0,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules: []*cilium.PortNetworkPolicyRule{{
				Precedence: uint32(policyTypes.HighestPriority.ToPassPrecedence()),
				Verdict: &cilium.PortNetworkPolicyRule_PassPrecedence{
					PassPrecedence: uint32(policyTypes.Priority(0xff).ToPassPrecedence()),
				},
			}},
		}, {
			Port:     443,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules: []*cilium.PortNetworkPolicyRule{{
				Precedence:     uint32(policyTypes.Priority(0x100).ToAllowPrecedence()),
				RemotePolicies: []uint32{1001, 1002},
			}},
		}}, obtained)
	})

	t.Run("wildcard_pass_keeps_same_priority_port_rules", func(t *testing.T) {
		passPriority := policyTypes.HighestPriority
		l4DirectionPolicy := &policy.L4DirectionPolicy{}
		*l4DirectionPolicy = policy.NewL4DirectionPolicyForTest(policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
			"0/TCP": {
				Port:     0,
				Protocol: api.ProtoAny, U8Proto: u8proto.ANY,
				PerSelectorPolicies: policy.L7DataMap{
					wildcardCachedSelector: {
						Priority: passPriority,
						Verdict:  types.Pass,
					},
				},
			},
			"80/TCP": {
				Port:     80,
				Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
				PerSelectorPolicies: policy.L7DataMap{
					cachedSelector1: {
						Priority: passPriority,
					},
					cachedSelector2: {
						Priority: passPriority,
						Verdict:  types.Deny,
					},
				},
			},
		}), []types.Priority{0})

		referredSelectors := make(SelectorSet)
		obtained := xds.getDirectionNetworkPolicy(ep, selectors, l4DirectionPolicy, true, false, false, "ingress", "", referredSelectors)
		obtained = projectLegacyPortPoliciesForTest(t, xds, selectors, uint64(ep.GetID()), ingressDirection, obtained, referredSelectors)
		require.EqualExportedValues(t, []*cilium.PortNetworkPolicy{{
			Port:     0,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules: []*cilium.PortNetworkPolicyRule{{
				Precedence: uint32(passPriority.ToPassPrecedence()),
				Verdict: &cilium.PortNetworkPolicyRule_PassPrecedence{
					PassPrecedence: uint32(policyTypes.LowestPriority.ToPassPrecedence()),
				},
			}},
		}, {
			Port:     80,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules: []*cilium.PortNetworkPolicyRule{{
				Precedence:     uint32(passPriority.ToDenyPrecedence()),
				Verdict:        DenyVerdict,
				RemotePolicies: []uint32{1001, 1003},
			}, {
				Precedence:     uint32(passPriority.ToAllowPrecedence()),
				RemotePolicies: []uint32{1001, 1002},
			}},
		}}, obtained)
	})

	t.Run("wildcard_pass_suppresses_lower_priority_port_rules", func(t *testing.T) {
		passPriority := policyTypes.HighestPriority
		l4DirectionPolicy := &policy.L4DirectionPolicy{}
		*l4DirectionPolicy = policy.NewL4DirectionPolicyForTest(policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
			"0/TCP": {
				Port:     0,
				Protocol: api.ProtoAny,
				PerSelectorPolicies: policy.L7DataMap{
					wildcardCachedSelector: {
						Priority: passPriority,
						Verdict:  types.Pass,
					},
				},
			},
			"80/TCP": {
				Port:     80,
				Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
				PerSelectorPolicies: policy.L7DataMap{
					cachedSelector1: {
						Priority: passPriority + 1,
					},
					cachedSelector2: {
						Priority: passPriority + 2,
						Verdict:  types.Deny,
					},
				},
			},
		}), []types.Priority{0})

		referredSelectors := make(SelectorSet)
		obtained := xds.getDirectionNetworkPolicy(ep, selectors, l4DirectionPolicy, true, false, false, "ingress", "", referredSelectors)
		obtained = projectLegacyPortPoliciesForTest(t, xds, selectors, uint64(ep.GetID()), ingressDirection, obtained, referredSelectors)
		require.EqualExportedValues(t, []*cilium.PortNetworkPolicy{{
			Port:     0,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules: []*cilium.PortNetworkPolicyRule{{
				Precedence: uint32(passPriority.ToPassPrecedence()),
				Verdict: &cilium.PortNetworkPolicyRule_PassPrecedence{
					PassPrecedence: uint32(policyTypes.LowestPriority.ToPassPrecedence()),
				},
			}},
		}}, obtained)
	})
}

func TestGetDirectionNetworkPolicyWildcardRedirect(t *testing.T) {
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()

	const listener1ProxyPort = uint16(19001)
	redirectEP := &listenerProxyUpdaterMock{
		ProxyUpdaterMock: &test.ProxyUpdaterMock{
			Id:   ep.Id,
			Ipv4: ep.Ipv4,
			Ipv6: ep.Ipv6,
		},
		listenerProxyPorts: map[string]uint16{
			"listener1": listener1ProxyPort,
		},
	}

	testCases := []struct {
		name             string
		redirectProtocol api.L4Proto
		redirectPriority policyTypes.Priority
		port80Policy     *policy.PerSelectorPolicy
		expected         []*cilium.PortNetworkPolicy
	}{
		{
			name:             "tcp_same_priority_keeps_port_rule",
			redirectProtocol: api.ProtoTCP,
			redirectPriority: policyTypes.HighestPriority,
			port80Policy:     &policy.PerSelectorPolicy{Priority: policyTypes.HighestPriority},
			expected: []*cilium.PortNetworkPolicy{
				{
					Port:     0,
					Protocol: envoy_config_core.SocketAddress_TCP,
					Rules: []*cilium.PortNetworkPolicyRule{{
						Precedence: uint32(policyTypes.HighestPriority.ToPrecedenceWithListenerPriority(false, true, policy.ListenerPriorityCRD)),
						ProxyId:    uint32(listener1ProxyPort),
					}},
				},
				{
					Port:     80,
					Protocol: envoy_config_core.SocketAddress_TCP,
					Rules: []*cilium.PortNetworkPolicyRule{{
						Precedence:     uint32(policyTypes.HighestPriority.ToAllowPrecedence()),
						RemotePolicies: []uint32{1001, 1002},
					}},
				},
			},
		},
		{
			name:             "tcp_higher_priority_suppresses_port_rule",
			redirectProtocol: api.ProtoTCP,
			redirectPriority: policyTypes.HighestPriority,
			port80Policy:     &policy.PerSelectorPolicy{Priority: policyTypes.Priority(1)},
			expected: []*cilium.PortNetworkPolicy{
				{
					Port:     0,
					Protocol: envoy_config_core.SocketAddress_TCP,
					Rules: []*cilium.PortNetworkPolicyRule{{
						Precedence: uint32(policyTypes.HighestPriority.ToPrecedenceWithListenerPriority(false, true, policy.ListenerPriorityCRD)),
						ProxyId:    uint32(listener1ProxyPort),
					}},
				},
			},
		},
		{
			name:             "any_protocol_redirect_is_sent_to_envoy_as_tcp",
			redirectProtocol: api.ProtoAny,
			redirectPriority: policyTypes.HighestPriority,
			port80Policy:     &policy.PerSelectorPolicy{Priority: policyTypes.HighestPriority},
			expected: []*cilium.PortNetworkPolicy{
				{
					Port:     0,
					Protocol: envoy_config_core.SocketAddress_TCP,
					Rules: []*cilium.PortNetworkPolicyRule{{
						Precedence: uint32(policyTypes.HighestPriority.ToPrecedenceWithListenerPriority(false, true, policy.ListenerPriorityCRD)),
						ProxyId:    uint32(listener1ProxyPort),
					}},
				},
				{
					Port:     80,
					Protocol: envoy_config_core.SocketAddress_TCP,
					Rules: []*cilium.PortNetworkPolicyRule{{
						Precedence:     uint32(policyTypes.HighestPriority.ToAllowPrecedence()),
						RemotePolicies: []uint32{1001, 1002},
					}},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			redirectPolicy := &policy.PerSelectorPolicy{
				Priority:         tc.redirectPriority,
				L7Parser:         policy.ParserTypeCRD,
				Listener:         "listener1",
				ListenerPriority: policy.ListenerPriorityCRD,
			}

			u8p, err := u8proto.ParseProtocol(string(tc.redirectProtocol))
			require.NoError(t, err)

			l4DirectionPolicy := &policy.L4DirectionPolicy{
				PortRules: policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
					"0/" + string(tc.redirectProtocol): {
						Port:     0,
						Protocol: tc.redirectProtocol, U8Proto: u8p,
						PerSelectorPolicies: policy.L7DataMap{
							wildcardCachedSelector: redirectPolicy,
						},
					},
					"80/TCP": {
						Port:     80,
						Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
						PerSelectorPolicies: policy.L7DataMap{
							cachedSelector1: tc.port80Policy,
						},
					},
				}),
			}

			referredSelectors := make(SelectorSet)
			obtained := xds.getDirectionNetworkPolicy(redirectEP, selectors, l4DirectionPolicy, true, false, false, "ingress", "", referredSelectors)
			obtained = projectLegacyPortPoliciesForTest(t, xds, selectors, uint64(redirectEP.GetID()), ingressDirection, obtained, referredSelectors)
			require.EqualExportedValues(t, tc.expected, obtained)
		})
	}
}

func TestCNPWildcardPortListenerRedirectToEnvoy(t *testing.T) {
	logger := hivetest.Logger(t)
	xds := testXdsServer(t)

	localIdentity := identity.NewIdentity(9001, labels.LabelArray{
		labels.NewLabel("id", "a", labels.LabelSourceK8s),
		labels.NewLabel(k8sConst.PodNamespaceLabel, "default", labels.LabelSourceK8s),
	}.Labels())

	idMgr := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(
		logger,
		identity.IdentityMap{localIdentity.ID: localIdentity.LabelArray},
		nil,
		envoypolicy.NewEnvoyL7RulesTranslator(logger, certificatemanager.NewMockSecretManagerInline()),
		idMgr,
		testpolicy.NewPolicyMetricsNoop(),
	)
	idMgr.Add(localIdentity)
	t.Cleanup(func() {
		idMgr.Remove(localIdentity)
	})

	cnpRule := &api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=a")),
		Egress: []api.EgressRule{{
			EgressCommonRule: api.EgressCommonRule{
				ToEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
			},
			ToPorts: []api.PortRule{{
				Ports: []api.PortProtocol{{
					Port:     "0",
					Protocol: api.ProtoAny,
				}},
				Listener: &api.Listener{
					EnvoyConfig: &api.EnvoyConfig{
						Kind: "CiliumEnvoyConfig",
						Name: "test-cec",
					},
					Name: "listener1",
				},
			}},
		}},
	}
	require.NoError(t, cnpRule.Sanitize())
	repo.MustAddList(api.Rules{cnpRule})

	selPolicy, _, err := repo.GetSelectorPolicy(localIdentity, 0, &dummyPolicyStats{}, ep.GetID())
	require.NoError(t, err)

	const listenerProxyPort = uint16(19001)
	const qualifiedListener = "default/test-cec/listener1"
	redirectEP := &listenerProxyUpdaterMock{
		ProxyUpdaterMock: &test.ProxyUpdaterMock{
			Id:   ep.Id,
			Ipv4: ep.Ipv4,
			Ipv6: ep.Ipv6,
		},
		listenerProxyPorts: map[string]uint16{
			qualifiedListener: listenerProxyPort,
		},
	}

	epp := selPolicy.DistillPolicy(logger, redirectEP, nil)
	t.Cleanup(func() {
		epp.Detach(logger)
	})

	obtained := xds.getDirectionNetworkPolicy(
		redirectEP,
		epp.GetPolicySelectors(),
		&epp.SelectorPolicy.L4Policy.Egress,
		true,
		false,
		false,
		"egress",
		"",
		nil,
	)

	require.Equal(t, []*cilium.PortNetworkPolicy{{
		Port:     0,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			Precedence: uint32(policyTypes.HighestPriority.ToPrecedenceWithListenerPriority(false, true, policy.ListenerPriorityCRD)),
			ProxyId:    uint32(listenerProxyPort),
		}},
	}}, obtained)
}

func TestGetNetworkPolicy(t *testing.T) {
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()
	obtained := buildProjectedLegacyNetworkPolicyForTest(t, xds, ep, selectors, []string{IPv4Addr}, L4Policy1, true, true, false, false, "")
	expected := &cilium.NetworkPolicy{
		EndpointIps:            []string{IPv4Addr},
		EndpointId:             uint64(ep.GetID()),
		IngressPerPortPolicies: ExpectedPerPortPolicies12,
		EgressPerPortPolicies:  ExpectedPerPortPolicies1,
	}
	require.EqualExportedValues(t, expected, obtained)
}

func TestGetNetworkPolicyWildcard(t *testing.T) {
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()
	obtained := buildProjectedLegacyNetworkPolicyForTest(t, xds, ep, selectors, []string{IPv4Addr}, L4Policy2, true, true, false, false, "")
	expected := &cilium.NetworkPolicy{
		EndpointIps:            []string{IPv4Addr},
		EndpointId:             uint64(ep.GetID()),
		IngressPerPortPolicies: ExpectedPerPortPolicies12Wildcard,
		EgressPerPortPolicies:  ExpectedPerPortPolicies1,
	}
	require.EqualExportedValues(t, expected, obtained)
}

func TestGetNetworkPolicyDeny(t *testing.T) {
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()
	obtained := buildProjectedLegacyNetworkPolicyForTest(t, xds, ep, selectors, []string{IPv4Addr}, L4Policy1RequiresV2, true, true, false, false, "")
	expected := &cilium.NetworkPolicy{
		EndpointIps:            []string{IPv4Addr},
		EndpointId:             uint64(ep.GetID()),
		IngressPerPortPolicies: ExpectedPerPortPolicies12RequiresV2,
		EgressPerPortPolicies:  ExpectedPerPortPolicies1,
	}
	require.EqualExportedValues(t, expected, obtained)
}

func TestGetNetworkPolicyWildcardDeny(t *testing.T) {
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()
	obtained := buildProjectedLegacyNetworkPolicyForTest(t, xds, ep, selectors, []string{IPv4Addr}, L4Policy1RequiresV2, true, true, false, false, "")
	expected := &cilium.NetworkPolicy{
		EndpointIps:            []string{IPv4Addr},
		EndpointId:             uint64(ep.GetID()),
		IngressPerPortPolicies: ExpectedPerPortPolicies12RequiresV2,
		EgressPerPortPolicies:  ExpectedPerPortPolicies1,
	}
	require.EqualExportedValues(t, expected, obtained)
}

func TestGetNetworkPolicyNil(t *testing.T) {
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()
	obtained := buildProjectedLegacyNetworkPolicyForTest(t, xds, ep, selectors, []string{IPv4Addr}, nil, true, true, false, false, "")
	expected := &cilium.NetworkPolicy{
		EndpointIps:            []string{IPv4Addr},
		EndpointId:             uint64(ep.GetID()),
		IngressPerPortPolicies: nil,
		EgressPerPortPolicies:  nil,
	}
	require.EqualExportedValues(t, expected, obtained)
}

func TestGetNetworkPolicyIngressNotEnforced(t *testing.T) {
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()
	obtained := buildProjectedLegacyNetworkPolicyForTest(t, xds, ep, selectors, []string{IPv4Addr}, L4Policy2, false, true, false, false, "")
	expected := &cilium.NetworkPolicy{
		EndpointIps:            []string{IPv4Addr},
		EndpointId:             uint64(ep.GetID()),
		IngressPerPortPolicies: allowAllPortNetworkPolicy,
		EgressPerPortPolicies:  ExpectedPerPortPolicies1,
	}
	require.EqualExportedValues(t, expected, obtained)
}

func TestGetNetworkPolicyEgressNotEnforced(t *testing.T) {
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()
	obtained := buildProjectedLegacyNetworkPolicyForTest(t, xds, ep, selectors, []string{IPv4Addr}, L4Policy1RequiresV2, true, false, false, false, "")
	expected := &cilium.NetworkPolicy{
		EndpointIps:            []string{IPv4Addr},
		EndpointId:             uint64(ep.GetID()),
		IngressPerPortPolicies: ExpectedPerPortPolicies12RequiresV2,
		EgressPerPortPolicies:  allowAllPortNetworkPolicy,
	}
	require.EqualExportedValues(t, expected, obtained)
}

func TestProjectedLegacyNetworkPolicyFromRulesL4L7Shadowing(t *testing.T) {
	xds := testXdsServer(t)

	localIdentity := newRuleDrivenTestIdentity(9001, "bar", "QA")
	remoteIdentity := newRuleDrivenTestIdentity(9002, "foo", "QA")

	repo := newRuleDrivenTestPolicyRepository(t, []*identity.Identity{localIdentity, remoteIdentity}, api.Rules{{
		EndpointSelector: api.NewESFromLabels(labels.ParseLabel("bar")),
		Ingress: []api.IngressRule{
			{
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseLabel("foo")),
					},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{{
							Method: "GET",
							HeaderMatches: []*api.HeaderMatch{{
								Mismatch: api.MismatchActionLog,
								Name:     ":path",
								Value:    "/bar",
							}},
						}},
					},
				}},
			},
		},
	}})

	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   9001,
		Ipv4: "10.0.0.1",
		Ipv6: "f00d::1",
	}}
	epp := distillFastPathEndpointPolicy(t, repo, localIdentity, redirectEP)
	t.Cleanup(func() {
		require.NoError(t, epp.Ready())
	})

	obtained := buildProjectedLegacyEndpointPolicyForTest(t, xds, redirectEP, epp)

	require.Equal(t, []string{"10.0.0.1", "f00d::1"}, obtained.EndpointIps)
	require.EqualValues(t, 9001, obtained.EndpointId)
	require.EqualExportedValues(t, allowAllPortNetworkPolicy, obtained.EgressPerPortPolicies)
	require.Len(t, obtained.IngressPerPortPolicies, 1)
	require.EqualValues(t, 80, obtained.IngressPerPortPolicies[0].Port)
	require.Equal(t, envoy_config_core.SocketAddress_TCP, obtained.IngressPerPortPolicies[0].Protocol)
	require.Len(t, obtained.IngressPerPortPolicies[0].Rules, 2)

	specificRule := obtained.IngressPerPortPolicies[0].Rules[0]
	wildcardRule := obtained.IngressPerPortPolicies[0].Rules[1]
	require.Greater(t, specificRule.Precedence, wildcardRule.Precedence)
	require.Equal(t, []uint32{uint32(remoteIdentity.ID)}, specificRule.RemotePolicies)
	require.Equal(t, &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{{
				Headers: []*envoy_config_route.HeaderMatcher{ExpectedHeaders3[0]},
				HeaderMatches: []*cilium.HeaderMatch{{
					Name:           ":path",
					Value:          "/bar",
					MismatchAction: cilium.HeaderMatch_CONTINUE_ON_MISMATCH,
				}},
			}},
		},
	}, specificRule.L7)
	require.True(t, isEmptyRuleButPrecedence(wildcardRule))
}

func TestProjectedLegacyNetworkPolicyFromRulesWildcardAllowAndSpecificHTTPPreserveBothRules(t *testing.T) {
	xds := testXdsServer(t)

	localIdentity := newRuleDrivenTestIdentity(9011, "bar", "QA")
	remoteIdentity := newRuleDrivenTestIdentity(9012, "foo", "QA")

	repo := newRuleDrivenTestPolicyRepository(t, []*identity.Identity{localIdentity, remoteIdentity}, api.Rules{{
		EndpointSelector: api.NewESFromLabels(labels.ParseLabel("bar")),
		Ingress: []api.IngressRule{
			{
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseLabel("foo")),
					},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{{
							Path:   "/bar",
							Method: "GET",
						}},
					},
				}},
			},
		},
	}})

	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   9011,
		Ipv4: "10.0.0.11",
		Ipv6: "f00d::11",
	}}
	epp := distillFastPathEndpointPolicy(t, repo, localIdentity, redirectEP)
	t.Cleanup(func() {
		require.NoError(t, epp.Ready())
	})

	obtained := buildProjectedLegacyEndpointPolicyForTest(t, xds, redirectEP, epp)

	require.Equal(t, []string{"10.0.0.11", "f00d::11"}, obtained.EndpointIps)
	require.EqualValues(t, 9011, obtained.EndpointId)
	require.EqualExportedValues(t, allowAllPortNetworkPolicy, obtained.EgressPerPortPolicies)
	require.Len(t, obtained.IngressPerPortPolicies, 1)
	require.EqualValues(t, 80, obtained.IngressPerPortPolicies[0].Port)
	require.Len(t, obtained.IngressPerPortPolicies[0].Rules, 2)

	specificRule := obtained.IngressPerPortPolicies[0].Rules[0]
	wildcardRule := obtained.IngressPerPortPolicies[0].Rules[1]
	require.Greater(t, specificRule.Precedence, wildcardRule.Precedence)
	require.Equal(t, []uint32{uint32(remoteIdentity.ID)}, specificRule.RemotePolicies)
	require.Equal(t, &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{{
				Headers: ExpectedHeaders3,
			}},
		},
	}, specificRule.L7)
	require.True(t, isEmptyRuleButPrecedence(wildcardRule))
}

func TestProjectedLegacyNetworkPolicyFromRulesL3DependentL7(t *testing.T) {
	xds := testXdsServer(t)

	localIdentity := newRuleDrivenTestIdentity(9021, "bar", "QA")
	fooIdentity := newRuleDrivenTestIdentity(9022, "foo", "QA")
	joeIdentity := newRuleDrivenTestIdentity(9023, "user=joe", "QA")

	repo := newRuleDrivenTestPolicyRepository(t, []*identity.Identity{localIdentity, fooIdentity, joeIdentity}, api.Rules{
		{
			EndpointSelector: api.NewESFromLabels(labels.ParseLabel("bar")),
			Ingress: []api.IngressRule{{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseLabel("foo")),
					},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{{
							Path:   "/bar",
							Method: "GET",
						}},
					},
				}},
			}},
		},
		{
			EndpointSelector: api.NewESFromLabels(labels.ParseLabel("bar")),
			Ingress: []api.IngressRule{{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseLabel("user=joe")),
					},
				},
			}},
		},
	})

	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   9021,
		Ipv4: "10.0.0.21",
		Ipv6: "f00d::21",
	}}
	epp := distillFastPathEndpointPolicy(t, repo, localIdentity, redirectEP)
	t.Cleanup(func() {
		require.NoError(t, epp.Ready())
	})

	obtained := buildProjectedLegacyEndpointPolicyForTest(t, xds, redirectEP, epp)

	require.EqualExportedValues(t, allowAllPortNetworkPolicy, obtained.EgressPerPortPolicies)
	require.Len(t, obtained.IngressPerPortPolicies, 2)
	require.EqualValues(t, 0, obtained.IngressPerPortPolicies[0].Port)
	require.EqualValues(t, 80, obtained.IngressPerPortPolicies[1].Port)
	require.Len(t, obtained.IngressPerPortPolicies[0].Rules, 1)
	require.Equal(t, []uint32{uint32(joeIdentity.ID)}, obtained.IngressPerPortPolicies[0].Rules[0].RemotePolicies)
	require.Len(t, obtained.IngressPerPortPolicies[1].Rules, 1)
	require.Equal(t, []uint32{uint32(fooIdentity.ID)}, obtained.IngressPerPortPolicies[1].Rules[0].RemotePolicies)
	require.Equal(t, &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{{
				Headers: ExpectedHeaders3,
			}},
		},
	}, obtained.IngressPerPortPolicies[1].Rules[0].L7)
}

func TestProjectedLegacyNetworkPolicyFromRulesIncrementalSelectorUpdate(t *testing.T) {
	xds := testXdsServer(t)

	localIdentity := newRuleDrivenTestIdentity(9031, "bar", "QA")
	repo := newRuleDrivenTestPolicyRepository(t, []*identity.Identity{localIdentity}, api.Rules{{
		EndpointSelector: api.NewESFromLabels(labels.ParseLabel("bar")),
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseLabel("user=joe")),
						api.NewESFromLabels(labels.ParseLabel("user=pete")),
						api.NewESFromLabels(labels.ParseLabel("foo")),
					},
				},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseLabel("foo")),
					},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{{
							Path:   "/bar",
							Method: "GET",
						}},
					},
				}},
			},
		},
	}})

	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   9031,
		Ipv4: "10.0.0.31",
		Ipv6: "f00d::31",
	}}
	epp := distillFastPathEndpointPolicy(t, repo, localIdentity, redirectEP)
	t.Cleanup(func() {
		require.NoError(t, epp.Ready())
	})

	require.EqualExportedValues(t, &cilium.NetworkPolicy{
		EndpointIps:            []string{"10.0.0.31", "f00d::31"},
		EndpointId:             9031,
		IngressPerPortPolicies: nil,
		EgressPerPortPolicies:  allowAllPortNetworkPolicy,
	}, buildProjectedLegacyEndpointPolicyForTest(t, xds, redirectEP, epp))

	addedIdentity := newRuleDrivenTestIdentity(9032, "foo", "QA")
	advanceEndpointPolicySelectors(t, repo, epp, identity.IdentityMap{
		addedIdentity.ID: addedIdentity.LabelArray,
	})

	obtained := buildProjectedLegacyEndpointPolicyForTest(t, xds, redirectEP, epp)
	require.EqualExportedValues(t, allowAllPortNetworkPolicy, obtained.EgressPerPortPolicies)
	require.Len(t, obtained.IngressPerPortPolicies, 2)
	require.EqualValues(t, 0, obtained.IngressPerPortPolicies[0].Port)
	require.EqualValues(t, 80, obtained.IngressPerPortPolicies[1].Port)
	require.Equal(t, []uint32{uint32(addedIdentity.ID)}, obtained.IngressPerPortPolicies[0].Rules[0].RemotePolicies)
	require.Equal(t, []uint32{uint32(addedIdentity.ID)}, obtained.IngressPerPortPolicies[1].Rules[0].RemotePolicies)
	require.Equal(t, &cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{{
				Headers: ExpectedHeaders3,
			}},
		},
	}, obtained.IngressPerPortPolicies[1].Rules[0].L7)
}

func TestProjectedLegacyNetworkPolicyCacheIncrementalSelectorUpdateAddsWildcardPortRule(t *testing.T) {
	localIdentity := newRuleDrivenTestIdentity(9041, "bar", "QA")
	repo := newRuleDrivenTestPolicyRepository(t, []*identity.Identity{localIdentity}, api.Rules{{
		EndpointSelector: api.NewESFromLabels(labels.ParseLabel("bar")),
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseLabel("user=joe")),
						api.NewESFromLabels(labels.ParseLabel("user=pete")),
						api.NewESFromLabels(labels.ParseLabel("foo")),
					},
				},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseLabel("foo")),
					},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{{
							Path:   "/bar",
							Method: "GET",
						}},
					},
				}},
			},
		},
	}})

	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   9041,
		Ipv4: "10.0.0.41",
		Ipv6: "f00d::41",
	}}
	epp := distillFastPathEndpointPolicy(t, repo, localIdentity, redirectEP)
	t.Cleanup(func() {
		require.NoError(t, epp.Ready())
	})

	xds, spy := newFastPathTestXDSServer(t, repo)

	err, revert, _ := xds.UpdateNetworkPolicy(redirectEP, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)
	require.Equal(t, 1, spy.upsertCalls)

	current := xds.networkPolicyCache.GetResources(NetworkPolicyTypeURL, 0, nil)
	networkPolicies, err := xds.GetNetworkPolicies(nil)
	require.NoError(t, err)
	initialPolicy := networkPolicies[redirectEP.Ipv4]
	require.NotNil(t, initialPolicy)
	require.Empty(t, initialPolicy.IngressPerPortPolicies)

	addedIdentity := newRuleDrivenTestIdentity(9042, "foo", "QA")
	advanceEndpointPolicySelectors(t, repo, epp, identity.IdentityMap{
		addedIdentity.ID: addedIdentity.LabelArray,
	})

	after := xds.networkPolicyCache.GetResources(NetworkPolicyTypeURL, 0, nil)
	require.Greater(t, after.Version, current.Version)
	require.Equal(t, 1, spy.upsertCalls)

	networkPolicies, err = xds.GetNetworkPolicies(nil)
	require.NoError(t, err)
	obtained := networkPolicies[redirectEP.Ipv4]
	require.NotNil(t, obtained)
	require.Len(t, obtained.IngressPerPortPolicies, 2)
	require.EqualValues(t, 0, obtained.IngressPerPortPolicies[0].Port)
	require.EqualValues(t, 80, obtained.IngressPerPortPolicies[1].Port)
	require.Equal(t, []uint32{uint32(addedIdentity.ID)}, obtained.IngressPerPortPolicies[0].Rules[0].RemotePolicies)
	require.Equal(t, []uint32{uint32(addedIdentity.ID)}, obtained.IngressPerPortPolicies[1].Rules[0].RemotePolicies)
}

var fullValuesTLSContext = &policy.TLSContext{
	TrustedCA:        "foo",
	CertificateChain: "certchain",
	PrivateKey:       "privatekey",
	Secret: k8sTypes.NamespacedName{
		Name:      "testsecret",
		Namespace: "testnamespace",
	},
}

var onlyTrustedCAOriginatingTLSContext = &policy.TLSContext{
	TrustedCA: "foo",
	Secret: k8sTypes.NamespacedName{
		Name:      "testsecret",
		Namespace: "testnamespace",
	},
}

var onlyTerminationDetailsTLSContext = &policy.TLSContext{
	CertificateChain: "certchain",
	PrivateKey:       "privatekey",
	Secret: k8sTypes.NamespacedName{
		Name:      "testsecret",
		Namespace: "testnamespace",
	},
}

var fullValuesTLSContextFromFile = &policy.TLSContext{
	TrustedCA:        "foo",
	CertificateChain: "certchain",
	PrivateKey:       "privatekey",
	FromFile:         true,
	Secret: k8sTypes.NamespacedName{
		Name:      "testsecret",
		Namespace: "testnamespace",
	},
}

var onlyTrustedCAOriginatingTLSContextFromFile = &policy.TLSContext{
	TrustedCA: "foo",
	FromFile:  true,
	Secret: k8sTypes.NamespacedName{
		Name:      "testsecret",
		Namespace: "testnamespace",
	},
}

var onlyTerminationDetailsTLSContextFromFile = &policy.TLSContext{
	CertificateChain: "certchain",
	PrivateKey:       "privatekey",
	FromFile:         true,
	Secret: k8sTypes.NamespacedName{
		Name:      "testsecret",
		Namespace: "testnamespace",
	},
}

// newL4PolicyTLSEgress is a small helper to reduce boilerplate.
func newL4PolicyTLSEgress(tls *policy.TLSContext) *policy.L4Policy {
	return &policy.L4Policy{
		Egress: policy.L4DirectionPolicy{PortRules: policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
			"443/TCP": {
				Port: 443, Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
				PerSelectorPolicies: policy.L7DataMap{
					cachedSelector1: &policy.PerSelectorPolicy{
						L7Parser:       "tls",
						OriginatingTLS: tls,
					},
				},
			},
		})},
	}
}

var L4PolicyTLSEgressFullValues = newL4PolicyTLSEgress(fullValuesTLSContext)

var L4PolicyTLSEgressFullValuesFromFile = newL4PolicyTLSEgress(fullValuesTLSContextFromFile)

var L4PolicyTLSEgressOnlyTrustedCA = newL4PolicyTLSEgress(onlyTrustedCAOriginatingTLSContext)

var L4PolicyTLSEgressOnlyTrustedCAFromFile = newL4PolicyTLSEgress(onlyTrustedCAOriginatingTLSContextFromFile)

func newEgressPortNetworkPolicyReturnVal(tls *cilium.TLSContext) []*cilium.PortNetworkPolicy {
	return []*cilium.PortNetworkPolicy{
		{
			Port:     443,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules: []*cilium.PortNetworkPolicyRule{{
				Precedence:         uint32(policyTypes.MaxAllowPrecedence + 1),
				RemotePolicies:     []uint32{1001, 1002},
				UpstreamTlsContext: tls,
			}},
		},
	}
}

var ciliumTLSContextOnlyValidatingSDSDetails = &cilium.TLSContext{
	ValidationContextSdsSecret: "cilium-secrets/testnamespace-testsecret",
}

var ciliumTLSContextOnlySDSDetails = &cilium.TLSContext{
	TlsSdsSecret: "cilium-secrets/testnamespace-testsecret",
}

var ciliumTLSContextOnlyTrustedCa = &cilium.TLSContext{
	TrustedCa: "foo",
}

var ciliumTLSContextAllDetails = &cilium.TLSContext{
	TrustedCa:        "foo",
	CertificateChain: "certchain",
	PrivateKey:       "privatekey",
}

var ciliumTLSContextOnlyTerminationDetails = &cilium.TLSContext{
	CertificateChain: "certchain",
	PrivateKey:       "privatekey",
}

var ExpectedPerPortPoliciesTLSEgress = newEgressPortNetworkPolicyReturnVal(ciliumTLSContextOnlyValidatingSDSDetails)

var ExpectedPerPortPoliciesTLSEgressNoSync = newEgressPortNetworkPolicyReturnVal(ciliumTLSContextOnlyTrustedCa)

var ExpectedPerPortPoliciesTLSEgressNoSyncUseFullContext = newEgressPortNetworkPolicyReturnVal(ciliumTLSContextAllDetails)

func newL4PolicyTLSIngress(tls *policy.TLSContext) *policy.L4Policy {
	return &policy.L4Policy{
		Ingress: policy.L4DirectionPolicy{PortRules: policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
			"443/TCP": {
				Port: 443, Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
				PerSelectorPolicies: policy.L7DataMap{
					cachedSelector1: &policy.PerSelectorPolicy{
						L7Parser:       "tls",
						TerminatingTLS: tls,
					},
				},
			},
		})},
	}
}

var L4PolicyTLSIngressFullValues = newL4PolicyTLSIngress(fullValuesTLSContext)

var L4PolicyTLSIngressFullValuesFromFile = newL4PolicyTLSIngress(fullValuesTLSContextFromFile)

var L4PolicyTLSIngressOnlyTerminationDetails = newL4PolicyTLSIngress(onlyTerminationDetailsTLSContext)

var L4PolicyTLSIngressOnlyTerminationDetailsFromFile = newL4PolicyTLSIngress(onlyTerminationDetailsTLSContextFromFile)

func newIngressPortNetworkPolicyReturnVal(tls *cilium.TLSContext) []*cilium.PortNetworkPolicy {
	return []*cilium.PortNetworkPolicy{
		{
			Port:     443,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules: []*cilium.PortNetworkPolicyRule{{
				Precedence:           uint32(policyTypes.MaxAllowPrecedence + 1),
				RemotePolicies:       []uint32{1001, 1002},
				DownstreamTlsContext: tls,
			}},
		},
	}
}

var ExpectedPerPortPoliciesTLSIngress = newIngressPortNetworkPolicyReturnVal(ciliumTLSContextOnlySDSDetails)

var ExpectedPerPortPoliciesTLSIngressNoSync = newIngressPortNetworkPolicyReturnVal(ciliumTLSContextOnlyTerminationDetails)

var ExpectedPerPortPoliciesTLSIngressNoSyncUseFullContext = newIngressPortNetworkPolicyReturnVal(ciliumTLSContextAllDetails)

var L4PolicyTLSFullContext = &policy.L4Policy{
	Ingress: policy.L4DirectionPolicy{PortRules: policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
		"443/TCP": {
			Port: 443, Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
			PerSelectorPolicies: policy.L7DataMap{
				cachedSelector1: &policy.PerSelectorPolicy{
					L7Parser: "tls",
					TerminatingTLS: &policy.TLSContext{
						CertificateChain: "terminatingCertchain",
						PrivateKey:       "terminatingKey",
						TrustedCA:        "terminatingCA",
						Secret: k8sTypes.NamespacedName{
							Name:      "terminating-tls",
							Namespace: "tlsns",
						},
					},
					OriginatingTLS: &policy.TLSContext{
						CertificateChain: "originatingCertchain",
						PrivateKey:       "originatingKey",
						TrustedCA:        "originatingCA",
						Secret: k8sTypes.NamespacedName{
							Name:      "originating-tls",
							Namespace: "tlsns",
						},
					},
				},
			},
			Ingress: true,
		},
	})},
}

var ExpectedPerPortPoliciesTLSFullContext = []*cilium.PortNetworkPolicy{
	{
		Port:     443,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
			RemotePolicies: []uint32{1001, 1002},
			DownstreamTlsContext: &cilium.TLSContext{
				CertificateChain: "terminatingCertchain",
				PrivateKey:       "terminatingKey",
				TrustedCa:        "terminatingCA",
			},
			UpstreamTlsContext: &cilium.TLSContext{
				CertificateChain: "originatingCertchain",
				PrivateKey:       "originatingKey",
				TrustedCa:        "originatingCA",
			},
		}},
	},
}

var ExpectedPerPortPoliciesTLSNotFullContext = []*cilium.PortNetworkPolicy{
	{
		Port:     443,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
			RemotePolicies: []uint32{1001, 1002},
			DownstreamTlsContext: &cilium.TLSContext{
				CertificateChain: "terminatingCertchain",
				PrivateKey:       "terminatingKey",
			},
			UpstreamTlsContext: &cilium.TLSContext{
				TrustedCa: "originatingCA",
			},
		}},
	},
}

var ExpectedPerPortPoliciesBothWaysTLSSDS = []*cilium.PortNetworkPolicy{
	{
		Port:     443,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
			RemotePolicies: []uint32{1001, 1002},
			DownstreamTlsContext: &cilium.TLSContext{
				TlsSdsSecret: "cilium-secrets/tlsns-terminating-tls",
			},
			UpstreamTlsContext: &cilium.TLSContext{
				ValidationContextSdsSecret: "cilium-secrets/tlsns-originating-tls",
			},
		}},
	},
}

func TestGetNetworkPolicyTLSInterception(t *testing.T) {
	type args struct {
		inputPolicy            *policy.L4Policy
		useFullTLSContext      bool
		useSDS                 bool
		policySecretsNamespace string
	}

	tests := []struct {
		name        string
		args        args
		wantEgress  []*cilium.PortNetworkPolicy
		wantIngress []*cilium.PortNetworkPolicy
	}{
		{
			name: "Egress Originating TLS Fully Populated with secret sync",
			args: args{
				inputPolicy:            L4PolicyTLSEgressFullValues,
				useFullTLSContext:      false,
				useSDS:                 true,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgress,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Fully Populated, UseFullTLSContext, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSEgressFullValues,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSyncUseFullContext,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Fully Populated, UseFullTLSContext, no sync, secretsNamespace",
			args: args{
				inputPolicy:            L4PolicyTLSEgressFullValues,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSyncUseFullContext,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Fully Populated, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSEgressFullValues,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Fully Populated, no sync, secretsNamespace",
			args: args{
				inputPolicy:            L4PolicyTLSEgressFullValues,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Only TrustedCA with secret sync",
			args: args{
				inputPolicy:            L4PolicyTLSEgressOnlyTrustedCA,
				useFullTLSContext:      false,
				useSDS:                 true,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgress,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Only TrustedCA, UseFullTLSContext, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSEgressOnlyTrustedCA,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Only TrustedCA, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSEgressOnlyTrustedCA,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Only TrustedCA, UseFullTLSContext, no sync, secretsNamespace",
			args: args{
				inputPolicy:            L4PolicyTLSEgressOnlyTrustedCA,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Only TrustedCA, no sync, secretsNamespace",
			args: args{
				inputPolicy:            L4PolicyTLSEgressOnlyTrustedCA,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Fully Populated with secret sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSEgressFullValuesFromFile,
				useFullTLSContext:      false,
				useSDS:                 true,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Fully Populated, UseFullTLSContext, no sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSEgressFullValuesFromFile,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSyncUseFullContext,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Fully Populated, no sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSEgressFullValuesFromFile,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Only TrustedCA with secret sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSEgressOnlyTrustedCAFromFile,
				useFullTLSContext:      false,
				useSDS:                 true,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Only TrustedCA, UseFullTLSContext, no sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSEgressOnlyTrustedCAFromFile,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Only TrustedCA, no sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSEgressOnlyTrustedCAFromFile,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Ingress Terminating TLS Fully Populated with secret sync",
			args: args{
				inputPolicy:            L4PolicyTLSIngressFullValues,
				useFullTLSContext:      false,
				useSDS:                 true,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngress,
		},
		{
			name: "Ingress Terminating TLS Fully Populated, UseFullTLSContext, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSIngressFullValues,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSyncUseFullContext,
		},
		{
			name: "Ingress Terminating TLS Fully Populated, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSIngressFullValues,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Fully Populated, UseFullTLSContext, no sync, secretsNamespace",
			args: args{
				inputPolicy:            L4PolicyTLSIngressFullValues,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSyncUseFullContext,
		},
		{
			name: "Ingress Terminating TLS Fully Populated, no sync, secretsNamespace",
			args: args{
				inputPolicy:            L4PolicyTLSIngressFullValues,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Only Termination details with secret sync",
			args: args{
				inputPolicy:            L4PolicyTLSIngressOnlyTerminationDetails,
				useFullTLSContext:      false,
				useSDS:                 true,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngress,
		},
		{
			name: "Ingress Terminating TLS Only Termination details, UseFullTLSContext, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSIngressOnlyTerminationDetails,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Only Termination details, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSIngressOnlyTerminationDetails,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Only Termination details, UseFullTLSContext, no sync, secretsNamespace",
			args: args{
				inputPolicy:            L4PolicyTLSIngressOnlyTerminationDetails,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Only Termination details, no sync, secretsNamespace",
			args: args{
				inputPolicy:            L4PolicyTLSIngressOnlyTerminationDetails,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Fully Populated with secret sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSIngressFullValuesFromFile,
				useFullTLSContext:      false,
				useSDS:                 true,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Fully Populated, UseFullTLSContext, no sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSIngressFullValuesFromFile,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSyncUseFullContext,
		},
		{
			name: "Ingress Terminating TLS Fully Populated, no sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSIngressFullValuesFromFile,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Only Termination details with secret sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSIngressOnlyTerminationDetailsFromFile,
				useFullTLSContext:      false,
				useSDS:                 true,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Only Termination details, UseFullTLSContext, no sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSIngressOnlyTerminationDetailsFromFile,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Only Termination details, no sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSIngressOnlyTerminationDetailsFromFile,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Both directions, full details, with sync",
			args: args{
				inputPolicy:            L4PolicyTLSFullContext,
				useFullTLSContext:      false,
				useSDS:                 true,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesBothWaysTLSSDS,
		},
		{
			name: "Both directions, full details, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSFullContext,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSNotFullContext,
		},
		// These next two tests check what happens when no sync is enabled, and useFullTLSContext is either true or false
		// (i.e., don't implement buggy behaviour).
		// When useFullTLSContext is false, we correctly strip out the CA for a terminatingTLS/downstreamTls and the
		// cert/key on originatingTLS/upstreamTls. Leaving them in can result in incorrect behaviour from Envoy when using
		// Cilium L7 policy that's not done via SDS, see https://github.com/cilium/cilium/issues/31761 for
		// full details.
		//
		// When Secret Sync and SDS are in use, the use of the TlsSdsSecret and ValidationContextSdsSecret mean that
		// SDS is not susceptible to that bug.
		{
			name: "Both directions, full details, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSFullContext,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSNotFullContext,
		},
		{
			name: "Both directions, full details, no sync, usefullcontext",
			args: args{
				inputPolicy:            L4PolicyTLSFullContext,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSFullContext,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xds := testXdsServer(t)
			selectors := testSelectorCache.GetSelectorSnapshot()
			obtained := buildProjectedLegacyNetworkPolicyForTest(t, xds, ep, selectors, []string{IPv4Addr}, tt.args.inputPolicy, true, true, tt.args.useFullTLSContext, tt.args.useSDS, tt.args.policySecretsNamespace)
			expected := &cilium.NetworkPolicy{
				EndpointIps:            []string{IPv4Addr},
				EndpointId:             uint64(ep.GetID()),
				IngressPerPortPolicies: tt.wantIngress,
				EgressPerPortPolicies:  tt.wantEgress,
			}
			require.EqualExportedValues(t, expected, obtained)
		})
	}
}

func Test_getPublicListenerAddress(t *testing.T) {
	type args struct {
		port uint16
		ipv4 bool
		ipv6 bool
	}
	tests := []struct {
		name string
		args args
		want *envoy_config_core.Address
	}{
		{
			name: "IPv4 only",
			args: args{
				port: 80,
				ipv4: true,
				ipv6: false,
			},
			want: &envoy_config_core.Address{
				Address: &envoy_config_core.Address_SocketAddress{
					SocketAddress: &envoy_config_core.SocketAddress{
						Protocol:      envoy_config_core.SocketAddress_TCP,
						Address:       "0.0.0.0",
						PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(80)},
					},
				},
			},
		},
		{
			name: "IPv6 only",
			args: args{
				port: 80,
				ipv4: false,
				ipv6: true,
			},
			want: &envoy_config_core.Address{
				Address: &envoy_config_core.Address_SocketAddress{
					SocketAddress: &envoy_config_core.SocketAddress{
						Protocol:      envoy_config_core.SocketAddress_TCP,
						Address:       "::",
						PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(80)},
					},
				},
			},
		},
		{
			name: "IPv4 and IPv6",
			args: args{
				port: 80,
				ipv4: true,
				ipv6: true,
			},
			want: &envoy_config_core.Address{
				Address: &envoy_config_core.Address_SocketAddress{
					SocketAddress: &envoy_config_core.SocketAddress{
						Protocol:      envoy_config_core.SocketAddress_TCP,
						Address:       "::",
						PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(80)},
						Ipv4Compat:    true,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPublicListenerAddress(tt.args.port, tt.args.ipv4, tt.args.ipv6)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_getLocalListenerAddresses(t *testing.T) {
	v4Local := &envoy_config_core.Address_SocketAddress{
		SocketAddress: &envoy_config_core.SocketAddress{
			Protocol:      envoy_config_core.SocketAddress_TCP,
			Address:       "127.0.0.1",
			PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(80)},
		},
	}

	v6Local := &envoy_config_core.Address_SocketAddress{
		SocketAddress: &envoy_config_core.SocketAddress{
			Protocol:      envoy_config_core.SocketAddress_TCP,
			Address:       "::1",
			PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(80)},
		},
	}
	type args struct {
		port uint16
		ipv4 bool
		ipv6 bool
	}
	tests := []struct {
		name           string
		args           args
		want           *envoy_config_core.Address
		wantAdditional []*envoy_config_listener.AdditionalAddress
	}{
		{
			name: "IPv4 only",
			args: args{
				port: 80,
				ipv4: true,
				ipv6: false,
			},
			want: &envoy_config_core.Address{
				Address: v4Local,
			},
		},
		{
			name: "IPv6 only",
			args: args{
				port: 80,
				ipv4: false,
				ipv6: true,
			},
			want: &envoy_config_core.Address{
				Address: v6Local,
			},
		},
		{
			name: "IPv4 and IPv6",
			args: args{
				port: 80,
				ipv4: true,
				ipv6: true,
			},
			want: &envoy_config_core.Address{
				Address: v4Local,
			},
			wantAdditional: []*envoy_config_listener.AdditionalAddress{{Address: &envoy_config_core.Address{Address: v6Local}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotAdditional := GetLocalListenerAddresses(tt.args.port, tt.args.ipv4, tt.args.ipv6)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantAdditional, gotAdditional)
		})
	}
}

func TestSelectorCacheUpdatedPublishesSelectorResources(t *testing.T) {
	xds := testDeltaXdsServer(t)

	xds.SelectorCacheUpdated(policy.SelectorUpdates{
		Revision: 5,
		Changes: []policy.SelectorChange{
			{ID: 1},
			{ID: 2, Selections: identity.NumericIdentitySlice{1001, 1002}},
		},
	})

	res1 := xds.networkPolicyResourceCache.Lookup(NetworkPolicyResourceTypeURL, xdsSelectorIdentifier(1))
	selector1 := res1.(*cilium.NetworkPolicyResource).GetSelector()
	require.Empty(t, selector1.GetRemoteIdentities())

	res2 := xds.networkPolicyResourceCache.Lookup(NetworkPolicyResourceTypeURL, xdsSelectorIdentifier(2))
	selector2 := res2.(*cilium.NetworkPolicyResource).GetSelector()
	require.Equal(t, []uint32{1001, 1002}, selector2.GetRemoteIdentities())
	require.Equal(t, policy.SelectorRevision(5), xds.selectorResourceRevision)

	xds.SelectorCacheUpdated(policy.SelectorUpdates{
		Revision: 6,
		Changes: []policy.SelectorChange{
			{ID: 1, Removed: true},
		},
	})

	res1 = xds.networkPolicyResourceCache.Lookup(NetworkPolicyResourceTypeURL, xdsSelectorIdentifier(1))
	require.Nil(t, res1)
	require.Equal(t, policy.SelectorRevision(6), xds.selectorResourceRevision)
}

func TestGetNetworkPoliciesDeltaSkipsSelectorResources(t *testing.T) {
	xds := testDeltaXdsServer(t)

	policyResource := &cilium.NetworkPolicyResource{
		Resource: &cilium.NetworkPolicyResource_Policy{
			Policy: &cilium.NetworkPolicy{
				EndpointId:  42,
				EndpointIps: []string{"10.0.0.1", "f00d::1"},
			},
		},
	}
	xds.networkPolicyResourceMutator.Upsert(NetworkPolicyResourceTypeURL, "42", policyResource, nil, nil, nil)

	xds.SelectorCacheUpdated(policy.SelectorUpdates{
		Revision: 1,
		Changes: []policy.SelectorChange{
			{ID: 7, Selections: identity.NumericIdentitySlice{1001}},
		},
	})

	selector := xds.networkPolicyResourceCache.Lookup(NetworkPolicyResourceTypeURL, xdsSelectorIdentifier(7))
	require.NotNil(t, selector)

	networkPolicies, err := xds.GetNetworkPolicies(nil)
	require.NoError(t, err)
	require.Len(t, networkPolicies, 2)
	require.Equal(t, policyResource.GetPolicy(), networkPolicies["10.0.0.1"])
	require.Equal(t, policyResource.GetPolicy(), networkPolicies["f00d::1"])
}

func TestWaitForSelectorRevision(t *testing.T) {
	xds := testDeltaXdsServer(t)

	done := make(chan error, 1)
	go func() {
		done <- xds.waitForSelectorRevision(3)
	}()

	xds.SelectorCacheUpdated(policy.SelectorUpdates{Revision: 3})
	require.NoError(t, <-done)
}

func TestWaitForSelectorRevisionCanceled(t *testing.T) {
	xds := testDeltaXdsServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	xds.runCtx = ctx
	xds.runCancel = cancel

	done := make(chan error, 1)
	go func() {
		done <- xds.waitForSelectorRevision(1)
	}()

	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestNoOpPolicyUpsertWaitsForCurrentVersionAfterSelectorUpdate(t *testing.T) {
	xds := testDeltaXdsServer(t)
	nodeID := "127.0.0.1"
	resourceName := "42"
	policyResource := &cilium.NetworkPolicyResource{
		Resource: &cilium.NetworkPolicyResource_Policy{
			Policy: &cilium.NetworkPolicy{EndpointId: 42},
		},
	}

	xds.networkPolicyResourceMutator.Upsert(NetworkPolicyResourceTypeURL, resourceName, policyResource, []string{nodeID}, nil, nil)
	xds.SelectorCacheUpdated(policy.SelectorUpdates{
		Revision: 1,
		Changes: []policy.SelectorChange{
			{ID: 7, Selections: identity.NumericIdentitySlice{1001}},
		},
	})

	current := xds.networkPolicyResourceCache.GetResources(NetworkPolicyResourceTypeURL, 0, nil)

	wg := completion.NewWaitGroup(context.Background())
	xds.networkPolicyResourceMutator.Upsert(NetworkPolicyResourceTypeURL, resourceName, policyResource, []string{nodeID}, wg, nil)

	done := make(chan error, 1)
	go func() {
		done <- wg.Wait()
	}()

	xds.resourceConfig[NetworkPolicyResourceTypeURL].AckObserver.HandleResourceVersionAck(current.Version-1, current.Version-1, nodeID, nil, NetworkPolicyResourceTypeURL, "")
	select {
	case err := <-done:
		t.Fatalf("wait completed too early: %v", err)
	default:
	}

	xds.resourceConfig[NetworkPolicyResourceTypeURL].AckObserver.HandleResourceVersionAck(current.Version, current.Version, nodeID, nil, NetworkPolicyResourceTypeURL, "")
	require.NoError(t, <-done)
}

func TestNewXDSServerSeedsSelectorSnapshot(t *testing.T) {
	logger := hivetest.Logger(t)
	repo := policy.NewPolicyRepository(logger, identity.IdentityMap{
		1001: labels.LabelArray{labels.NewLabel("id", "a", labels.LabelSourceK8s)},
	}, nil, nil, nil, testpolicy.NewPolicyMetricsNoop())
	sc := repo.GetSelectorCache()
	fooSelector, _ := sc.AddIdentitySelectorForTest(nil, api.NewESFromLabels(labels.ParseSelectLabel("k8s:id=a")))
	barSelector, _ := sc.AddIdentitySelectorForTest(nil, api.NewESFromLabels(labels.ParseSelectLabel("k8s:id=b")))
	snapshot := sc.GetSelectorSnapshot()
	t.Cleanup(func() { snapshot.Invalidate() })

	secretManager := certificatemanager.NewMockSecretManagerInline()
	xds := newXDSServer(logger, nil, nil, repo, newLocalEndpointStore(), xdsServerConfig{
		metrics: envoyxds.NewXDSMetric(),
	}, secretManager)
	t.Cleanup(xds.stop)

	res1 := xds.networkPolicyResourceCache.Lookup(NetworkPolicyResourceTypeURL, xdsSelectorIdentifier(fooSelector.Id()))
	selector1 := res1.(*cilium.NetworkPolicyResource).GetSelector()
	require.Equal(t, []uint32{1001}, selector1.GetRemoteIdentities())

	res2 := xds.networkPolicyResourceCache.Lookup(NetworkPolicyResourceTypeURL, xdsSelectorIdentifier(barSelector.Id()))
	selector2 := res2.(*cilium.NetworkPolicyResource).GetSelector()
	require.Empty(t, selector2.GetRemoteIdentities())

	require.Equal(t, snapshot.Revision, xds.selectorResourceRevision)
}

func policySelectorNames(policyResource *cilium.NetworkPolicy) []string {
	var selectorNames []string
	collect := func(portPolicies []*cilium.PortNetworkPolicy) {
		for _, portPolicy := range portPolicies {
			for _, rule := range portPolicy.Rules {
				selectorNames = append(selectorNames, rule.Selectors...)
			}
		}
	}
	collect(policyResource.IngressPerPortPolicies)
	collect(policyResource.EgressPerPortPolicies)
	slices.Sort(selectorNames)
	return slices.Compact(selectorNames)
}

func cachedSelectorNames(selectors SelectorSet) []string {
	names := make([]string, 0, len(selectors))
	for selector := range selectors {
		names = append(names, xdsSelectorIdentifier(selector.Id()))
	}
	slices.Sort(names)
	return slices.Compact(names)
}

func onlyCachedSelector(t *testing.T, selectors SelectorSet) policy.CachedSelector {
	t.Helper()

	require.Len(t, selectors, 1)
	for selector := range selectors {
		return selector
	}
	t.Fatal("expected one selector")
	return nil
}

func selectorPublicationForRevision(t *testing.T, xds *xdsServer, revision policy.SelectorRevision) *selectorPublication {
	t.Helper()

	index := slices.IndexFunc(xds.pendingSelectorPublications, func(publication *selectorPublication) bool {
		return publication.revision == revision
	})
	if index < 0 {
		t.Fatalf("expected selector publication for revision %d", revision)
	}
	return xds.pendingSelectorPublications[index]
}

func selectorLookupFromSetForTest(snapshot policy.SelectorSnapshot, referredSelectors SelectorSet) map[string][]uint32 {
	selectorLookup := make(map[string][]uint32, len(referredSelectors))
	for selector := range referredSelectors {
		selectorLookup[xdsSelectorIdentifier(selector.Id())] = selector.GetSelectionsAt(snapshot).AsUint32Slice()
	}
	return selectorLookup
}

func projectLegacyRuleForTest(t *testing.T, xds *xdsServer, snapshot policy.SelectorSnapshot, endpointID uint64, direction string, port uint32, rule *cilium.PortNetworkPolicyRule, referredSelectors SelectorSet) *cilium.PortNetworkPolicyRule {
	t.Helper()

	projectedSource := xds.networkPolicyCache.(*projectedNetworkPolicySource)
	projectedRules := projectedSource.projectLegacyPortNetworkPolicyRules(
		endpointID,
		direction,
		port,
		[]*cilium.PortNetworkPolicyRule{proto.Clone(rule).(*cilium.PortNetworkPolicyRule)},
		selectorLookupFromSetForTest(snapshot, referredSelectors),
	)
	if len(projectedRules) == 0 {
		return nil
	}
	require.Len(t, projectedRules, 1)
	return projectedRules[0]
}

func projectLegacyPortPoliciesForTest(t *testing.T, xds *xdsServer, snapshot policy.SelectorSnapshot, endpointID uint64, direction string, policies []*cilium.PortNetworkPolicy, referredSelectors SelectorSet) []*cilium.PortNetworkPolicy {
	t.Helper()

	networkPolicy := &cilium.NetworkPolicy{
		EndpointId:  endpointID,
		EndpointIps: []string{IPv4Addr},
	}
	switch direction {
	case ingressDirection:
		networkPolicy.IngressPerPortPolicies = policies
	case egressDirection:
		networkPolicy.EgressPerPortPolicies = policies
	default:
		t.Fatalf("unsupported direction %q", direction)
	}

	projected := projectLegacyNetworkPolicyForTest(t, xds, snapshot, networkPolicy, referredSelectors)
	if direction == ingressDirection {
		return projected.GetIngressPerPortPolicies()
	}
	return projected.GetEgressPerPortPolicies()
}

func projectLegacyNetworkPolicyForTest(t *testing.T, xds *xdsServer, snapshot policy.SelectorSnapshot, networkPolicy *cilium.NetworkPolicy, referredSelectors SelectorSet) *cilium.NetworkPolicy {
	t.Helper()

	projectedSource := xds.networkPolicyCache.(*projectedNetworkPolicySource)
	projected, ok := projectedSource.projectLegacyNetworkPolicy(networkPolicy, selectorLookupFromSetForTest(snapshot, referredSelectors))
	require.True(t, ok)
	return projected
}

func buildProjectedLegacyNetworkPolicyForTest(t *testing.T, xds *xdsServer, ep endpoint.EndpointUpdater, selectors policy.SelectorSnapshot, names []string, l4Policy *policy.L4Policy, ingressPolicyEnforced, egressPolicyEnforced, useFullTLSContext, useSDS bool, policySecretsNamespace string) *cilium.NetworkPolicy {
	t.Helper()

	resource, referredSelectors, err := xds.buildNetworkPolicyResource(ep, selectors, names, l4Policy, ingressPolicyEnforced, egressPolicyEnforced, useFullTLSContext, useSDS, policySecretsNamespace)
	require.NoError(t, err)
	return projectLegacyNetworkPolicyForTest(t, xds, selectors, resource.GetPolicy(), referredSelectors)
}

func buildProjectedLegacyEndpointPolicyForTest(t *testing.T, xds *xdsServer, ep endpoint.EndpointUpdater, epp *policy.EndpointPolicy) *cilium.NetworkPolicy {
	t.Helper()

	return buildProjectedLegacyNetworkPolicyForTest(
		t,
		xds,
		ep,
		epp.GetPolicySelectors(),
		ep.GetPolicyNames(),
		&epp.SelectorPolicy.L4Policy,
		epp.SelectorPolicy.IngressPolicyEnabled,
		epp.SelectorPolicy.EgressPolicyEnabled,
		false,
		false,
		"",
	)
}

func newRuleDrivenTestIdentity(id identity.NumericIdentity, labelStrings ...string) *identity.Identity {
	labelArray := make(labels.LabelArray, 0, len(labelStrings))
	for _, labelString := range labelStrings {
		labelArray = append(labelArray, labels.ParseLabel(labelString))
	}
	return identity.NewIdentity(id, labelArray.Labels())
}

func newRuleDrivenTestPolicyRepository(t *testing.T, identities []*identity.Identity, rules api.Rules) policy.PolicyRepository {
	t.Helper()

	logger := hivetest.Logger(t)
	idMgr := identitymanager.NewIDManager(logger)
	identityMap := make(identity.IdentityMap, len(identities))
	for _, identity := range identities {
		identityMap[identity.ID] = identity.LabelArray
	}

	repo := policy.NewPolicyRepository(
		logger,
		identityMap,
		nil,
		envoypolicy.NewEnvoyL7RulesTranslator(logger, certificatemanager.NewMockSecretManagerInline()),
		idMgr,
		testpolicy.NewPolicyMetricsNoop(),
	)
	for _, identity := range identities {
		idMgr.Add(identity)
	}
	t.Cleanup(func() {
		for _, identity := range identities {
			idMgr.Remove(identity)
		}
	})

	for i := range rules {
		require.NoError(t, rules[i].Sanitize())
	}
	repo.MustAddList(rules)

	return repo
}

func hasSelectorPublicationRevision(xds *xdsServer, revision policy.SelectorRevision) bool {
	return slices.ContainsFunc(xds.pendingSelectorPublications, func(publication *selectorPublication) bool {
		return publication.revision == revision
	})
}

func TestAddRenderedSelectorTracksSelectorSet(t *testing.T) {
	referredSelectors := make(SelectorSet)

	require.Equal(t, xdsSelectorIdentifier(cachedRequiresV2Selector1.Id()), referredSelectors.add(cachedRequiresV2Selector1))
	require.Equal(t, xdsSelectorIdentifier(cachedSelector1.Id()), referredSelectors.add(cachedSelector1))
	require.Equal(t, xdsSelectorIdentifier(cachedRequiresV2Selector1.Id()), referredSelectors.add(cachedRequiresV2Selector1))

	require.Equal(t, []string{
		xdsSelectorIdentifier(cachedSelector1.Id()),
		xdsSelectorIdentifier(cachedRequiresV2Selector1.Id()),
	}, cachedSelectorNames(referredSelectors))
}

func TestUpdateNetworkPolicyNPRDSRetainsRenderedSelectors(t *testing.T) {
	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   48,
		Ipv4: "10.0.0.8",
		Ipv6: "f00d::8",
	}}
	repo, _, epp := newFastPathTestEndpointPolicy(t, redirectEP)
	xds, _ := newFastPathTestXDSServer(t, repo)

	err, revert, _ := xds.UpdateNetworkPolicy(redirectEP, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)

	published := xds.publishedNetworkPolicies[redirectEP.GetID()]
	resource := xds.networkPolicyResourceCache.Lookup(NetworkPolicyResourceTypeURL, strconv.FormatUint(redirectEP.GetID(), 10))
	require.NotNil(t, resource)
	policyResource := resource.(*cilium.NetworkPolicyResource).GetPolicy()
	require.NotNil(t, policyResource)
	require.Equal(t, policySelectorNames(policyResource), cachedSelectorNames(published.selectors))
}

func TestUpdateNetworkPolicyFastPathAllowsStaleSelectorSnapshotWhenUnchanged(t *testing.T) {
	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   481,
		Ipv4: "10.0.0.81",
		Ipv6: "f00d::81",
	}}
	repo, _, epp := newFastPathTestEndpointPolicy(t, redirectEP)
	xds, spy := newFastPathTestXDSServer(t, repo)

	err, revert, _ := xds.UpdateNetworkPolicy(redirectEP, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)
	require.Equal(t, 1, spy.upsertCalls)

	require.NoError(t, epp.Ready())
	stale := epp.GetPolicySelectors()
	require.False(t, stale.IsValid())

	err, revert, _ = xds.UpdateNetworkPolicy(redirectEP, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)
	require.Equal(t, 1, spy.upsertCalls)
}

func TestNPRDSRetainedSelectorStaysLiveAfterEndpointPolicyDetach(t *testing.T) {
	logger := hivetest.Logger(t)
	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   49,
		Ipv4: "10.0.0.9",
		Ipv6: "f00d::9",
	}}
	repo, _, epp := newFastPathTestEndpointPolicy(t, redirectEP)
	xds, _ := newFastPathTestXDSServer(t, repo)

	err, revert, _ := xds.UpdateNetworkPolicy(redirectEP, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)

	published := xds.publishedNetworkPolicies[redirectEP.GetID()]
	selectorName := xdsSelectorIdentifier(onlyCachedSelector(t, published.selectors).Id())

	require.NoError(t, epp.Ready())
	epp.Detach(logger)

	var selectorWG sync.WaitGroup
	repo.GetSelectorCache().UpdateIdentities(identity.IdentityMap{
		9003: labels.LabelArray{labels.NewLabel("id", "b", labels.LabelSourceK8s)},
	}, nil, &selectorWG)
	selectorWG.Wait()

	resource := xds.networkPolicyResourceCache.Lookup(NetworkPolicyResourceTypeURL, selectorName)
	require.NotNil(t, resource)
	selector := resource.(*cilium.NetworkPolicyResource).GetSelector()
	require.ElementsMatch(t, []uint32{9002, 9003}, selector.GetRemoteIdentities())
}

func TestRemoveNetworkPolicyReleasesRetainedSelectorAfterDetach(t *testing.T) {
	logger := hivetest.Logger(t)
	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   50,
		Ipv4: "10.0.0.10",
		Ipv6: "f00d::10",
	}}
	repo, _, epp := newFastPathTestEndpointPolicy(t, redirectEP)
	xds, _ := newFastPathTestXDSServer(t, repo)

	err, revert, _ := xds.UpdateNetworkPolicy(redirectEP, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)

	published := xds.publishedNetworkPolicies[redirectEP.GetID()]
	retainedSelector := onlyCachedSelector(t, published.selectors)
	selectorName := xdsSelectorIdentifier(retainedSelector.Id())

	require.NoError(t, epp.Ready())
	epp.Detach(logger)
	xds.RemoveNetworkPolicy(redirectEP)

	require.NotContains(t, xds.selectorRefs, retainedSelector)
	require.NotNil(t, xds.networkPolicyResourceCache.Lookup(NetworkPolicyResourceTypeURL, selectorName))
}

func TestSharedNPRDSRetainedSelectorReleasedAfterLastPolicyRemoved(t *testing.T) {
	logger := hivetest.Logger(t)
	redirectEP1 := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   51,
		Ipv4: "10.0.0.11",
		Ipv6: "f00d::11",
	}}
	repo, localIdentity, epp1 := newFastPathTestEndpointPolicy(t, redirectEP1)
	redirectEP2 := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   52,
		Ipv4: "10.0.0.12",
		Ipv6: "f00d::12",
	}}
	epp2 := distillFastPathEndpointPolicy(t, repo, localIdentity, redirectEP2)
	xds, _ := newFastPathTestXDSServer(t, repo)

	err, revert, _ := xds.UpdateNetworkPolicy(redirectEP1, epp1, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)
	err, revert, _ = xds.UpdateNetworkPolicy(redirectEP2, epp2, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)

	published := xds.publishedNetworkPolicies[redirectEP1.GetID()]
	cs := onlyCachedSelector(t, published.selectors)
	selectorID := cs.Id()
	selectorName := xdsSelectorIdentifier(selectorID)
	require.Equal(t, 2, xds.selectorRefs[cs])

	require.NoError(t, epp1.Ready())
	epp1.Detach(logger)
	require.NoError(t, epp2.Ready())
	epp2.Detach(logger)

	xds.RemoveNetworkPolicy(redirectEP1)
	require.Equal(t, 1, xds.selectorRefs[cs])
	require.NotNil(t, xds.networkPolicyResourceCache.Lookup(NetworkPolicyResourceTypeURL, selectorName))

	xds.RemoveNetworkPolicy(redirectEP2)
	_, exists := xds.selectorRefs[cs]
	require.False(t, exists)
	require.NotNil(t, xds.networkPolicyResourceCache.Lookup(NetworkPolicyResourceTypeURL, selectorName))
}

func TestUpdateNetworkPolicyDeltaWaitsForSelectorPublicationAfterSelectorUpdate(t *testing.T) {
	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   42,
		Ipv4: "10.0.0.1",
		Ipv6: "f00d::1",
	}}
	repo, localIdentity, epp := newFastPathTestEndpointPolicy(t, redirectEP)
	xds, spy := newFastPathTestXDSServer(t, repo)
	enablePolicyAckWaits(xds)

	err, revert, _ := xds.UpdateNetworkPolicy(redirectEP, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)
	require.Equal(t, 1, spy.upsertCalls)

	advanceEndpointPolicySelectors(t, repo, epp, identity.IdentityMap{
		9003: labels.LabelArray{labels.NewLabel("id", "b", labels.LabelSourceK8s)},
	})
	publication := selectorPublicationForRevision(t, xds, epp.GetPolicySelectors().Revision)

	wg := completion.NewWaitGroup(context.Background())
	err, revert, _ = xds.UpdateNetworkPolicy(redirectEP, epp, wg)
	require.NoError(t, err)
	require.NotNil(t, revert)
	require.Equal(t, 1, spy.upsertCalls)
	require.Equal(t, epp.GetPolicySelectors().Revision, xds.publishedNetworkPolicies[redirectEP.GetID()].selectorRevision)

	done := make(chan error, 1)
	go func() {
		done <- wg.Wait()
	}()

	nodeID := getNodeIDs(redirectEP, &epp.SelectorPolicy.L4Policy)[0]
	xds.resourceConfig[NetworkPolicyResourceTypeURL].AckObserver.HandleResourceVersionAck(publication.version-1, publication.version-1, nodeID, nil, NetworkPolicyResourceTypeURL, "")
	select {
	case err := <-done:
		t.Fatalf("wait completed too early: %v", err)
	default:
	}

	xds.resourceConfig[NetworkPolicyResourceTypeURL].AckObserver.HandleResourceVersionAck(publication.version, publication.version, nodeID, nil, NetworkPolicyResourceTypeURL, "")
	require.NoError(t, <-done)
	require.False(t, hasSelectorPublicationRevision(xds, epp.GetPolicySelectors().Revision))

	// Keep localIdentity live for the lifetime of the policy repository.
	require.Equal(t, identity.NumericIdentity(9001), localIdentity.ID)
}

func TestUpdateNetworkPolicyDeltaSelectorPublicationNACKCompletesWaitSuccessfully(t *testing.T) {
	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   421,
		Ipv4: "10.0.0.21",
		Ipv6: "f00d::21",
	}}
	repo, _, epp := newFastPathTestEndpointPolicy(t, redirectEP)
	xds, spy := newFastPathTestXDSServer(t, repo)
	enablePolicyAckWaits(xds)

	err, revert, _ := xds.UpdateNetworkPolicy(redirectEP, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)

	advanceEndpointPolicySelectors(t, repo, epp, identity.IdentityMap{
		9003: labels.LabelArray{labels.NewLabel("id", "b", labels.LabelSourceK8s)},
	})
	publication := selectorPublicationForRevision(t, xds, epp.GetPolicySelectors().Revision)

	wg := completion.NewWaitGroup(context.Background())
	err, revert, _ = xds.UpdateNetworkPolicy(redirectEP, epp, wg)
	require.NoError(t, err)
	require.NotNil(t, revert)
	require.Equal(t, 1, spy.upsertCalls)

	done := make(chan error, 1)
	go func() {
		done <- wg.Wait()
	}()

	nodeID := getNodeIDs(redirectEP, &epp.SelectorPolicy.L4Policy)[0]
	xds.resourceConfig[NetworkPolicyResourceTypeURL].AckObserver.HandleResourceVersionAck(publication.version-1, publication.version, nodeID, nil, NetworkPolicyResourceTypeURL, "selector stale")
	require.NoError(t, <-done)
	require.False(t, hasSelectorPublicationRevision(xds, epp.GetPolicySelectors().Revision))
}

func TestProjectedNPDSSatisfiesSelectorPublicationWait(t *testing.T) {
	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   422,
		Ipv4: "10.0.0.22",
		Ipv6: "f00d::22",
	}}
	repo, _, epp := newFastPathTestEndpointPolicy(t, redirectEP)
	xds, spy := newFastPathTestXDSServer(t, repo)
	enablePolicyAckWaits(xds)

	err, revert, finalize := xds.UpdateNetworkPolicy(redirectEP, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)
	require.NotNil(t, finalize)
	finalize()

	advanceEndpointPolicySelectors(t, repo, epp, identity.IdentityMap{
		9003: labels.LabelArray{labels.NewLabel("id", "b", labels.LabelSourceK8s)},
	})
	selectorPublicationForRevision(t, xds, epp.GetPolicySelectors().Revision)

	wg := completion.NewWaitGroup(context.Background())
	err, revert, _ = xds.UpdateNetworkPolicy(redirectEP, epp, wg)
	require.NoError(t, err)
	require.NotNil(t, revert)
	require.Equal(t, 1, spy.upsertCalls)

	done := make(chan error, 1)
	go func() {
		done <- wg.Wait()
	}()

	current := xds.networkPolicyCache.GetResources(NetworkPolicyTypeURL, 0, nil)
	nodeID := getNodeIDs(redirectEP, &epp.SelectorPolicy.L4Policy)[0]
	resourceName := strconv.FormatUint(redirectEP.GetID(), 10)

	xds.resourceConfig[NetworkPolicyTypeURL].AckObserver.HandleResourceVersionAck(current.Version-1, current.Version-1, nodeID, []string{resourceName}, NetworkPolicyTypeURL, "")
	select {
	case err := <-done:
		t.Fatalf("wait completed too early: %v", err)
	default:
	}

	xds.resourceConfig[NetworkPolicyTypeURL].AckObserver.HandleResourceVersionAck(current.Version, current.Version, nodeID, []string{resourceName}, NetworkPolicyTypeURL, "")
	require.NoError(t, <-done)
	require.False(t, hasSelectorPublicationRevision(xds, epp.GetPolicySelectors().Revision))
}

func TestUpdateNetworkPolicySotWSkipsMutationWhenUnchanged(t *testing.T) {
	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   43,
		Ipv4: "10.0.0.2",
		Ipv6: "f00d::2",
	}}
	repo, _, epp := newFastPathTestEndpointPolicy(t, redirectEP)
	xds, spy := newFastPathTestXDSServer(t, repo)

	err, revert, _ := xds.UpdateNetworkPolicy(redirectEP, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)
	require.Equal(t, 1, spy.upsertCalls)

	current := xds.networkPolicyCache.GetResources(NetworkPolicyTypeURL, 0, nil)

	err, revert, _ = xds.UpdateNetworkPolicy(redirectEP, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)
	require.Equal(t, 1, spy.upsertCalls)

	after := xds.networkPolicyCache.GetResources(NetworkPolicyTypeURL, 0, nil)
	require.Equal(t, current.Version, after.Version)
}

func TestUpdateNetworkPolicyWaitsOnPendingOperationForSameEndpoint(t *testing.T) {
	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   430,
		Ipv4: "10.0.0.43",
		Ipv6: "f00d::43",
	}}
	repo, _, epp := newFastPathTestEndpointPolicy(t, redirectEP)
	xds, spy := newFastPathTestXDSServer(t, repo)
	enablePolicyAckWaits(xds)

	wg1 := completion.NewWaitGroup(context.Background())
	err, revert1, finalize1 := xds.UpdateNetworkPolicy(redirectEP, epp, wg1)
	require.NoError(t, err)
	require.NotNil(t, revert1)
	require.NotNil(t, finalize1)
	require.Equal(t, 1, spy.upsertCalls)

	current := xds.networkPolicyCache.GetResources(NetworkPolicyTypeURL, 0, nil)

	wg2 := completion.NewWaitGroup(context.Background())
	err, revert2, finalize2 := xds.UpdateNetworkPolicy(redirectEP, epp, wg2)
	require.NoError(t, err)
	require.NotNil(t, revert2)
	require.NotNil(t, finalize2)
	require.Equal(t, 1, spy.upsertCalls)

	done1 := make(chan error, 1)
	go func() {
		done1 <- wg1.Wait()
	}()
	done2 := make(chan error, 1)
	go func() {
		done2 <- wg2.Wait()
	}()

	nodeID := getNodeIDs(redirectEP, &epp.SelectorPolicy.L4Policy)[0]
	resourceName := strconv.FormatUint(redirectEP.GetID(), 10)

	xds.resourceConfig[NetworkPolicyTypeURL].AckObserver.HandleResourceVersionAck(current.Version-1, current.Version-1, nodeID, []string{resourceName}, NetworkPolicyTypeURL, "")
	select {
	case err := <-done1:
		t.Fatalf("first wait completed too early: %v", err)
	case err := <-done2:
		t.Fatalf("second wait completed too early: %v", err)
	default:
	}

	xds.resourceConfig[NetworkPolicyTypeURL].AckObserver.HandleResourceVersionAck(current.Version, current.Version, nodeID, []string{resourceName}, NetworkPolicyTypeURL, "")
	require.NoError(t, <-done1)
	require.NoError(t, <-done2)

	finalize1()
	finalize2()
}

func TestUpdateNetworkPolicySotWProjectionUpdatesWhenSelectorsChange(t *testing.T) {
	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   44,
		Ipv4: "10.0.0.3",
		Ipv6: "f00d::3",
	}}
	repo, _, epp := newFastPathTestEndpointPolicy(t, redirectEP)
	xds, spy := newFastPathTestXDSServer(t, repo)

	err, revert, _ := xds.UpdateNetworkPolicy(redirectEP, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)
	require.Equal(t, 1, spy.upsertCalls)

	current := xds.networkPolicyCache.GetResources(NetworkPolicyTypeURL, 0, nil)

	advanceEndpointPolicySelectors(t, repo, epp, identity.IdentityMap{
		9003: labels.LabelArray{labels.NewLabel("id", "b", labels.LabelSourceK8s)},
	})

	err, revert, _ = xds.UpdateNetworkPolicy(redirectEP, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)
	require.Equal(t, 1, spy.upsertCalls)

	after := xds.networkPolicyCache.GetResources(NetworkPolicyTypeURL, 0, nil)
	require.Greater(t, after.Version, current.Version)
}

func TestUpdateNetworkPolicyFallsBackWhenPolicyNamesChange(t *testing.T) {
	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   45,
		Ipv4: "10.0.0.4",
		Ipv6: "f00d::4",
	}}
	repo, _, epp := newFastPathTestEndpointPolicy(t, redirectEP)
	xds, spy := newFastPathTestXDSServer(t, repo)

	err, revert, _ := xds.UpdateNetworkPolicy(redirectEP, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)
	require.Equal(t, 1, spy.upsertCalls)

	redirectEP.Ipv4 = "10.0.0.5"

	err, revert, _ = xds.UpdateNetworkPolicy(redirectEP, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)
	require.Equal(t, 2, spy.upsertCalls)
}

func TestUpdateNetworkPolicyRevertRestoresPublishedState(t *testing.T) {
	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   46,
		Ipv4: "10.0.0.6",
		Ipv6: "f00d::6",
	}}
	repo, localIdentity, epp1 := newFastPathTestEndpointPolicy(t, redirectEP)
	xds, spy := newFastPathTestXDSServer(t, repo)

	err, revert1, _ := xds.UpdateNetworkPolicy(redirectEP, epp1, nil)
	require.NoError(t, err)
	require.NotNil(t, revert1)
	require.Equal(t, 1, spy.upsertCalls)

	epp2 := distillFastPathEndpointPolicy(t, repo, localIdentity, redirectEP)

	err, revert2, _ := xds.UpdateNetworkPolicy(redirectEP, epp2, nil)
	require.NoError(t, err)
	require.NotNil(t, revert2)
	require.Equal(t, 2, spy.upsertCalls)

	require.NoError(t, revert2())

	err, revert3, _ := xds.UpdateNetworkPolicy(redirectEP, epp2, nil)
	require.NoError(t, err)
	require.NotNil(t, revert3)
	require.Equal(t, 3, spy.upsertCalls)
}

func TestUpdateNetworkPolicyOverlappingFailuresRestoreLastCommittedState(t *testing.T) {
	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   64,
		Ipv4: "10.0.0.64",
		Ipv6: "f00d::64",
	}}
	repo, localIdentity, epp1 := newFastPathTestEndpointPolicy(t, redirectEP)
	xds, _ := newFastPathTestXDSServer(t, repo)

	err, revert1, finalize1 := xds.UpdateNetworkPolicy(redirectEP, epp1, nil)
	require.NoError(t, err)
	require.NotNil(t, revert1)
	require.NotNil(t, finalize1)
	finalize1()

	epp2 := distillFastPathEndpointPolicy(t, repo, localIdentity, redirectEP)
	err, revert2, _ := xds.UpdateNetworkPolicy(redirectEP, epp2, nil)
	require.NoError(t, err)
	require.NotNil(t, revert2)

	epp3 := distillFastPathEndpointPolicy(t, repo, localIdentity, redirectEP)
	err, revert3, _ := xds.UpdateNetworkPolicy(redirectEP, epp3, nil)
	require.NoError(t, err)
	require.NotNil(t, revert3)
	require.Same(t, epp3, xds.publishedNetworkPolicies[redirectEP.GetID()].policy)

	require.NoError(t, revert2())
	require.Same(t, epp3, xds.publishedNetworkPolicies[redirectEP.GetID()].policy)

	require.NoError(t, revert3())
	require.Same(t, epp1, xds.publishedNetworkPolicies[redirectEP.GetID()].policy)
	require.Empty(t, xds.pendingNetworkPolicyOperations[redirectEP.GetID()])
}

func TestUpdateNetworkPolicyFinalizeSupersedesOlderFailedOperation(t *testing.T) {
	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   65,
		Ipv4: "10.0.0.65",
		Ipv6: "f00d::65",
	}}
	repo, localIdentity, epp1 := newFastPathTestEndpointPolicy(t, redirectEP)
	xds, _ := newFastPathTestXDSServer(t, repo)

	err, revert1, finalize1 := xds.UpdateNetworkPolicy(redirectEP, epp1, nil)
	require.NoError(t, err)
	require.NotNil(t, revert1)
	require.NotNil(t, finalize1)
	finalize1()

	epp2 := distillFastPathEndpointPolicy(t, repo, localIdentity, redirectEP)
	err, revert2, _ := xds.UpdateNetworkPolicy(redirectEP, epp2, nil)
	require.NoError(t, err)
	require.NotNil(t, revert2)

	epp3 := distillFastPathEndpointPolicy(t, repo, localIdentity, redirectEP)
	err, _, finalize3 := xds.UpdateNetworkPolicy(redirectEP, epp3, nil)
	require.NoError(t, err)
	require.NotNil(t, finalize3)

	require.NoError(t, revert2())
	require.Same(t, epp3, xds.publishedNetworkPolicies[redirectEP.GetID()].policy)

	finalize3()
	require.Same(t, epp3, xds.publishedNetworkPolicies[redirectEP.GetID()].policy)
	require.Empty(t, xds.pendingNetworkPolicyOperations[redirectEP.GetID()])
}

func TestRemoveNetworkPolicyClearsPublishedState(t *testing.T) {
	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   47,
		Ipv4: "10.0.0.7",
		Ipv6: "f00d::7",
	}}
	repo, _, epp := newFastPathTestEndpointPolicy(t, redirectEP)
	xds, spy := newFastPathTestXDSServer(t, repo)

	err, revert, _ := xds.UpdateNetworkPolicy(redirectEP, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)
	require.Equal(t, 1, spy.upsertCalls)

	xds.RemoveNetworkPolicy(redirectEP)

	err, revert, _ = xds.UpdateNetworkPolicy(redirectEP, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revert)
	require.Equal(t, 2, spy.upsertCalls)
}

func TestUpdateNetworkPolicyWaitsOnCanonicalNPRDSWhenNPDSListenersPresent(t *testing.T) {
	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   60,
		Ipv4: "10.0.0.60",
		Ipv6: "f00d::60",
	}}
	repo, _, epp := newFastPathTestEndpointPolicy(t, redirectEP)
	xds, spy := newPolicyWaitTestXDSServer(t, repo)
	enablePolicyAckWaits(xds)

	err, revert, _ := xds.UpdateNetworkPolicy(redirectEP, epp, completion.NewWaitGroup(context.Background()))
	require.NoError(t, err)
	require.NotNil(t, revert)
	require.Len(t, spy.calls, 1)
	require.Equal(t, "upsert", spy.calls[0].kind)
	require.Equal(t, NetworkPolicyResourceTypeURL, spy.calls[0].typeURL)
	require.True(t, spy.calls[0].waited)
	require.True(t, spy.calls[0].callback)
}

func TestUpdateNetworkPolicySkipsACKWaitWithoutNPDSListeners(t *testing.T) {
	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   61,
		Ipv4: "10.0.0.61",
		Ipv6: "f00d::61",
	}}
	repo, _, epp := newFastPathTestEndpointPolicy(t, redirectEP)
	xds, spy := newPolicyWaitTestXDSServer(t, repo)

	err, revert, _ := xds.UpdateNetworkPolicy(redirectEP, epp, completion.NewWaitGroup(context.Background()))
	require.NoError(t, err)
	require.NotNil(t, revert)
	require.Len(t, spy.calls, 1)
	require.Equal(t, NetworkPolicyResourceTypeURL, spy.calls[0].typeURL)
	require.False(t, spy.calls[0].waited)
	require.False(t, spy.calls[0].callback)
}

func TestProjectedNPDSNACKFailsCanonicalPolicyWait(t *testing.T) {
	redirectEP := &listenerProxyUpdaterMock{ProxyUpdaterMock: &test.ProxyUpdaterMock{
		Id:   62,
		Ipv4: "10.0.0.62",
		Ipv6: "f00d::62",
	}}
	repo, _, epp := newFastPathTestEndpointPolicy(t, redirectEP)
	xds, _ := newPolicyWaitTestXDSServer(t, repo)
	enablePolicyAckWaits(xds)

	wg := completion.NewWaitGroup(context.Background())
	err, revert, _ := xds.UpdateNetworkPolicy(redirectEP, epp, wg)
	require.NoError(t, err)
	require.NotNil(t, revert)

	done := make(chan error, 1)
	go func() {
		done <- wg.Wait()
	}()

	current := xds.networkPolicyCache.GetResources(NetworkPolicyTypeURL, 0, nil)
	nodeID := getNodeIDs(redirectEP, &epp.SelectorPolicy.L4Policy)[0]
	resourceName := strconv.FormatUint(redirectEP.GetID(), 10)
	xds.resourceConfig[NetworkPolicyTypeURL].AckObserver.HandleResourceVersionAck(current.Version-1, current.Version, nodeID, []string{resourceName}, NetworkPolicyTypeURL, "projected npds nack")

	err = <-done
	require.Error(t, err)
	var proxyErr *envoyxds.ProxyError
	require.ErrorAs(t, err, &proxyErr)
	require.Equal(t, envoyxds.ErrNackReceived, proxyErr.Err)
}

func testDeltaXdsServer(t *testing.T) *xdsServer { return testxdsServer(t) }

func testXdsServer(t *testing.T) *xdsServer { return testxdsServer(t) }

func testxdsServer(t *testing.T) *xdsServer {
	logger := hivetest.Logger(t)
	secretManager := certificatemanager.NewMockSecretManagerInline()
	xds := newXDSServer(logger, nil, nil, nil, newLocalEndpointStore(), xdsServerConfig{
		metrics: envoyxds.NewXDSMetric(),
	}, secretManager)
	xds.l7RulesTranslator = envoypolicy.NewEnvoyL7RulesTranslator(logger, secretManager)
	return xds
}

func (s *xdsServer) GetNetworkPolicies(resourceNames []string) (map[string]*cilium.NetworkPolicy, error) {
	resources := s.networkPolicyCache.GetResources(NetworkPolicyTypeURL, 0, resourceNames)
	networkPolicies := make(map[string]*cilium.NetworkPolicy, len(resources.VersionedResources))
	for i := range resources.VersionedResources {
		resource := resources.VersionedResources[i].Resource
		var networkPolicy *cilium.NetworkPolicy
		r, ok := resource.(*cilium.NetworkPolicyResource)
		if ok && r != nil {
			networkPolicy = r.GetPolicy()
		} else {
			networkPolicy = resources.VersionedResources[i].Resource.(*cilium.NetworkPolicy)
		}
		if networkPolicy == nil {
			continue
		}
		for _, ip := range networkPolicy.EndpointIps {
			networkPolicies[ip] = networkPolicy
		}
	}
	return networkPolicies, nil
}

type spyAckingResourceMutator struct {
	delegate    envoyxds.AckingResourceMutator
	upsertCalls int
	calls       []spyAckingResourceMutatorCall
}

type spyAckingResourceMutatorCall struct {
	kind     string
	typeURL  string
	waited   bool
	callback bool
}

func (m *spyAckingResourceMutator) Upsert(typeURL string, resourceName string, resource proto.Message, nodeIDs []string, wg *completion.WaitGroup, callback func(error)) envoyxds.AckingResourceMutatorRevertFunc {
	m.upsertCalls++
	m.calls = append(m.calls, spyAckingResourceMutatorCall{
		kind:     "upsert",
		typeURL:  typeURL,
		waited:   wg != nil,
		callback: callback != nil,
	})
	return m.delegate.Upsert(typeURL, resourceName, resource, nodeIDs, wg, callback)
}

func (m *spyAckingResourceMutator) Delete(typeURL string, resourceName string, nodeIDs []string, wg *completion.WaitGroup, callback func(error)) envoyxds.AckingResourceMutatorRevertFunc {
	return m.delegate.Delete(typeURL, resourceName, nodeIDs, wg, callback)
}

func (m *spyAckingResourceMutator) CancelCompletions(typeURL string) {
	m.delegate.CancelCompletions(typeURL)
}

func newFastPathTestXDSServer(t *testing.T, repo policy.PolicyRepository) (*xdsServer, *spyAckingResourceMutator) {
	return newPolicyWaitTestXDSServer(t, repo)
}

func newPolicyWaitTestXDSServer(t *testing.T, repo policy.PolicyRepository) (*xdsServer, *spyAckingResourceMutator) {
	logger := hivetest.Logger(t)
	secretManager := certificatemanager.NewMockSecretManagerInline()
	xds := newXDSServer(logger, nil, nil, repo, newLocalEndpointStore(), xdsServerConfig{
		metrics: envoyxds.NewXDSMetric(),
	}, secretManager)
	xds.l7RulesTranslator = envoypolicy.NewEnvoyL7RulesTranslator(logger, secretManager)
	t.Cleanup(xds.stop)

	nprdsSpy := &spyAckingResourceMutator{delegate: xds.networkPolicyResourceMutator}
	xds.networkPolicyResourceMutator = nprdsSpy
	return xds, nprdsSpy
}

func enablePolicyAckWaits(xds *xdsServer) {
	xds.mutex.Lock()
	defer xds.mutex.Unlock()

	xds.npdsListeners.Add("test-npds")
}

func newFastPathTestEndpointPolicy(t *testing.T, ep *listenerProxyUpdaterMock) (policy.PolicyRepository, *identity.Identity, *policy.EndpointPolicy) {
	logger := hivetest.Logger(t)
	localIdentity := identity.NewIdentity(9001, labels.LabelArray{
		labels.NewLabel("id", "a", labels.LabelSourceK8s),
	}.Labels())
	remoteIdentity := identity.NewIdentity(9002, labels.LabelArray{
		labels.NewLabel("id", "b", labels.LabelSourceK8s),
	}.Labels())

	idMgr := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(logger, identity.IdentityMap{
		localIdentity.ID:  localIdentity.LabelArray,
		remoteIdentity.ID: remoteIdentity.LabelArray,
	}, nil, nil, idMgr, testpolicy.NewPolicyMetricsNoop())
	idMgr.Add(localIdentity)
	t.Cleanup(func() {
		idMgr.Remove(localIdentity)
	})

	rule := &api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=a")),
		Ingress: []api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(labels.ParseSelectLabel("id=b")),
				},
			},
			ToPorts: []api.PortRule{{
				Ports: []api.PortProtocol{{
					Port:     "80",
					Protocol: api.ProtoTCP,
				}},
			}},
		}},
	}
	require.NoError(t, rule.Sanitize())
	repo.MustAddList(api.Rules{rule})

	return repo, localIdentity, distillFastPathEndpointPolicy(t, repo, localIdentity, ep)
}

func distillFastPathEndpointPolicy(t *testing.T, repo policy.PolicyRepository, localIdentity *identity.Identity, ep *listenerProxyUpdaterMock) *policy.EndpointPolicy {
	logger := hivetest.Logger(t)
	selPolicy, _, err := repo.GetSelectorPolicy(localIdentity, 0, &dummyPolicyStats{}, ep.GetID())
	require.NoError(t, err)

	epp := selPolicy.DistillPolicy(logger, ep, nil)
	t.Cleanup(func() {
		epp.Detach(logger)
	})
	return epp
}

func advanceEndpointPolicySelectors(t *testing.T, repo policy.PolicyRepository, epp *policy.EndpointPolicy, added identity.IdentityMap) {
	var selectorWG sync.WaitGroup
	mutated := repo.GetSelectorCache().UpdateIdentities(added, nil, &selectorWG)
	require.False(t, mutated)
	selectorWG.Wait()

	closer, _ := epp.ConsumeMapChanges()
	closer()
}
