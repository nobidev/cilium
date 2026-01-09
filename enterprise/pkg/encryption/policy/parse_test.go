//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

func Test_parsePeerPorts(t *testing.T) {
	type args struct {
		ports []iso_v1alpha1.PortProtocol
	}
	tests := []struct {
		name    string
		args    args
		want    []portProto
		wantErr bool
	}{
		{
			name: "regular port list",
			args: args{
				ports: []iso_v1alpha1.PortProtocol{
					{
						Port:     8080,
						Protocol: "TCP",
					},
					{
						Port:     53,
						Protocol: "UDP",
					},
				},
			},
			want: []portProto{
				{
					port:  8080,
					proto: u8proto.TCP,
				},
				{
					port:  53,
					proto: u8proto.UDP,
				},
			},
		},
		{
			name: "invalid protocol",
			args: args{
				ports: []iso_v1alpha1.PortProtocol{
					{
						Port:     8080,
						Protocol: "HTTP",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid port",
			args: args{
				ports: []iso_v1alpha1.PortProtocol{
					{
						Port:     0,
						Protocol: "UDP",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "ANY protocol",
			args: args{
				ports: []iso_v1alpha1.PortProtocol{
					{
						Port:     8080,
						Protocol: "ANY",
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePeerPorts(tt.args.ports)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func Test_parseSelector(t *testing.T) {
	podSelector := &slim_metav1.LabelSelector{
		MatchLabels: map[string]slim_metav1.MatchLabelsValue{
			"foo": "bar",
		},
		MatchExpressions: []slim_metav1.LabelSelectorRequirement{
			{
				Key:      "baz",
				Operator: "In",
				Values:   []string{"a", "b"},
			},
		},
	}

	namespaceSelector := &slim_metav1.LabelSelector{
		MatchLabels: map[string]slim_metav1.MatchLabelsValue{
			"baz": "qux",
		},
		MatchExpressions: []slim_metav1.LabelSelectorRequirement{
			{
				Key:      "bat",
				Operator: "In",
				Values:   []string{"e", "f"},
			},
		},
	}

	translatedNamespaceSelector := &slim_metav1.LabelSelector{
		MatchLabels: map[string]slim_metav1.MatchLabelsValue{
			"io.cilium.k8s.namespace.labels.baz": "qux",
		},
		MatchExpressions: []slim_metav1.LabelSelectorRequirement{
			{
				Key:      "io.cilium.k8s.namespace.labels.bat",
				Operator: "In",
				Values:   []string{"e", "f"},
			},
		},
	}

	type args struct {
		namespace         string
		podSelector       *slim_metav1.LabelSelector
		namespaceSelector *slim_metav1.LabelSelector
	}
	tests := []struct {
		name string
		args args
		want api.EndpointSelector
	}{
		{
			name: "empty selector without namespace",
			args: args{
				namespace: "",
			},
			want: api.WildcardEndpointSelector,
		},
		{
			name: "pod selector without namespace",
			args: args{
				namespace:   "",
				podSelector: podSelector,
			},
			want: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, podSelector),
		},
		{
			name: "namespace selector without namespace",
			args: args{
				namespace:         "",
				namespaceSelector: namespaceSelector,
			},
			want: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, translatedNamespaceSelector),
		},
		{
			name: "pod and namespace selector without namespace",
			args: args{
				namespace:         "",
				podSelector:       podSelector,
				namespaceSelector: namespaceSelector,
			},
			want: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, translatedNamespaceSelector, podSelector),
		},
		{
			name: "empty selector with namespace",
			args: args{
				namespace: "test-namespace",
			},
			want: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					k8sConst.PodNamespaceLabel: "test-namespace",
				},
			}),
		},
		{
			name: "empty pod selector with namespace",
			args: args{
				namespace:   "test-namespace",
				podSelector: &slim_metav1.LabelSelector{},
			},
			want: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					k8sConst.PodNamespaceLabel: "test-namespace",
				},
			}),
		},
		{
			name: "pod selector with namespace",
			args: args{
				namespace:   "test-namespace",
				podSelector: podSelector,
			},
			want: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, podSelector, &slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					k8sConst.PodNamespaceLabel: "test-namespace",
				},
			}),
		},
		{
			name: "namespace selector with namespace",
			args: args{
				namespace:         "test-namespace",
				namespaceSelector: namespaceSelector,
			},
			want: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, translatedNamespaceSelector),
		},
		{
			name: "pod and namespace selector with namespace",
			args: args{
				namespace:         "test-namespace",
				podSelector:       podSelector,
				namespaceSelector: namespaceSelector,
			},
			want: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, translatedNamespaceSelector, podSelector),
		},
		{
			name: "pod selector and empty namespace selector with namespace",
			args: args{
				namespace:         "test-namespace",
				podSelector:       podSelector,
				namespaceSelector: &slim_metav1.LabelSelector{},
			},
			want: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &slim_metav1.LabelSelector{
				MatchExpressions: []slim_metav1.LabelSelectorRequirement{
					allowAllNamespacesRequirement,
				},
			}, podSelector),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, parseSelector(tt.args.namespace, tt.args.namespaceSelector, tt.args.podSelector))
		})
	}
}

func Test_parseEncryptionPolicy(t *testing.T) {
	type args struct {
		resourceKey resource.Key
		spec        iso_v1alpha1.ClusterwideEncryptionPolicySpec
	}
	subjectNamespaceSelector := &slim_metav1.LabelSelector{
		MatchLabels: map[string]slim_metav1.MatchLabelsValue{
			"kubernetes.io/metadata.name": "subject-namespace",
		},
	}
	subjectPodSelector := &slim_metav1.LabelSelector{
		MatchLabels: map[string]slim_metav1.MatchLabelsValue{
			"app": "subject-pod",
		},
	}
	peer1NamespaceSelector := &slim_metav1.LabelSelector{
		MatchLabels: map[string]slim_metav1.MatchLabelsValue{
			"kubernetes.io/metadata.name": "peer1-namespace",
		},
	}
	peer1PodSelector := &slim_metav1.LabelSelector{
		MatchLabels: map[string]slim_metav1.MatchLabelsValue{
			"app": "peer1-pod",
		},
	}
	peer2NamespaceSelector := &slim_metav1.LabelSelector{
		MatchLabels: map[string]slim_metav1.MatchLabelsValue{
			"kubernetes.io/metadata.name": "peer2-namespace",
		},
	}
	peer2PodSelector := &slim_metav1.LabelSelector{
		MatchLabels: map[string]slim_metav1.MatchLabelsValue{
			"app": "peer2-pod",
		},
	}
	tests := []struct {
		name    string
		args    args
		want    []parsedSelectorRule
		wantErr bool
	}{
		{
			name: "regular policy with two rules",
			args: args{
				resourceKey: resource.Key{
					Name: "encrypt-foo",
				},
				spec: iso_v1alpha1.ClusterwideEncryptionPolicySpec{
					NamespaceSelector: subjectNamespaceSelector,
					PodSelector:       subjectPodSelector,
					Peers: []iso_v1alpha1.ClusterwideEncryptionPeerSelector{
						{
							NamespaceSelector: peer1NamespaceSelector,
							PodSelector:       peer1PodSelector,
							Ports: []iso_v1alpha1.PortProtocol{
								{
									Port:     8080,
									Protocol: "TCP",
								},
							},
						},
						{
							NamespaceSelector: peer2NamespaceSelector,
							PodSelector:       peer2PodSelector,
							Ports: []iso_v1alpha1.PortProtocol{
								{
									Port:     53,
									Protocol: "UDP",
								},
							},
						},
					},
				},
			},
			want: []parsedSelectorRule{
				{
					subject: policyTypes.NewLabelSelector(parseSelector("", subjectNamespaceSelector, subjectPodSelector)),
					peer:    policyTypes.NewLabelSelector(parseSelector("", peer1NamespaceSelector, peer1PodSelector)),
					peerPorts: []portProto{
						{
							port:  8080,
							proto: u8proto.TCP,
						},
					},
				},
				{
					subject: policyTypes.NewLabelSelector(parseSelector("", subjectNamespaceSelector, subjectPodSelector)),
					peer:    policyTypes.NewLabelSelector(parseSelector("", peer2NamespaceSelector, peer2PodSelector)),
					peerPorts: []portProto{
						{
							port:  53,
							proto: u8proto.UDP,
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing subject namespace selector",
			args: args{
				resourceKey: resource.Key{
					Name: "encrypt-foo",
				},
				spec: iso_v1alpha1.ClusterwideEncryptionPolicySpec{
					NamespaceSelector: nil,
					PodSelector:       subjectPodSelector,
					Peers: []iso_v1alpha1.ClusterwideEncryptionPeerSelector{
						{
							NamespaceSelector: peer1NamespaceSelector,
							PodSelector:       peer1PodSelector,
							Ports: []iso_v1alpha1.PortProtocol{
								{
									Port:     8080,
									Protocol: "TCP",
								},
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "missing peer namespace selector",
			args: args{
				resourceKey: resource.Key{
					Name: "encrypt-foo",
				},
				spec: iso_v1alpha1.ClusterwideEncryptionPolicySpec{
					NamespaceSelector: subjectNamespaceSelector,
					PodSelector:       subjectPodSelector,
					Peers: []iso_v1alpha1.ClusterwideEncryptionPeerSelector{
						{
							NamespaceSelector: nil,
							PodSelector:       peer1PodSelector,
							Ports: []iso_v1alpha1.PortProtocol{
								{
									Port:     8080,
									Protocol: "TCP",
								},
							},
						},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseEncryptionPolicy(tt.args.resourceKey, tt.args.spec)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.want, got)
		})
	}
}
