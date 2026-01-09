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
	"errors"
	"fmt"
	"maps"
	"slices"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	networkPolicy "github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	allowAllNamespacesRequirement = slim_metav1.LabelSelectorRequirement{
		Key:      k8sConst.PodNamespaceLabel,
		Operator: slim_metav1.LabelSelectorOpExists,
	}
)

// portProto is a port and proto pair
type portProto struct {
	port  uint16
	proto u8proto.U8proto
}

// parsedSelectorRule is a parsed IsovalentClusterwideEncryptionPolicy rule
// where selectors and ports have been converted into Cilium-native types.
type parsedSelectorRule struct {
	subject   *policyTypes.LabelSelector
	peer      *policyTypes.LabelSelector
	peerPorts []portProto
}

// parsePeerPorts parses the IsovalentClusterwideEncryptionPolicy port list into
// Cilium-native types.
func parsePeerPorts(ports []iso_v1alpha1.PortProtocol) ([]portProto, error) {
	peerPorts := make([]portProto, 0, len(ports))
	for _, p := range ports {
		proto, err := u8proto.ParseProtocol(p.Protocol)
		switch {
		case err != nil:
			return nil, err
		case proto == u8proto.ANY:
			return nil, errors.New("protocol ANY not supported")
		case p.Port == 0:
			return nil, errors.New("invalid port: 0")
		}

		peerPorts = append(peerPorts, portProto{
			port:  p.Port,
			proto: proto,
		})
	}

	return peerPorts, nil
}

// parsePodSelector translates a podSelector into a Cilium-native EndpointSelector.
// An optional namespace can be provided to ensure the selector is evaluated only
// the context of the provided namespace.
func parsePodSelector(namespace string, podSelectorIn *slim_metav1.LabelSelector) *slim_metav1.LabelSelector {
	podSelector := &slim_metav1.LabelSelector{
		MatchLabels: maps.Clone(podSelectorIn.MatchLabels),
	}
	if namespace != "" {
		// The PodSelector should only reflect to the same namespace
		// the policy is being stored, thus we add the namespace to
		// the MatchLabels map.
		if podSelector.MatchLabels == nil {
			podSelector.MatchLabels = make(map[string]slim_metav1.MatchLabelsValue, 1)
		}
		podSelector.MatchLabels[k8sConst.PodNamespaceLabel] = namespace
	}

	if len(podSelectorIn.MatchExpressions) > 0 {
		podSelector.MatchExpressions = make([]slim_metav1.LabelSelectorRequirement, 0, len(podSelectorIn.MatchExpressions))
		for _, matchExp := range podSelectorIn.MatchExpressions {
			lsr := slim_metav1.LabelSelectorRequirement{
				Key:      matchExp.Key,
				Operator: matchExp.Operator,
				Values:   slices.Clone(matchExp.Values),
			}
			podSelector.MatchExpressions = append(podSelector.MatchExpressions, lsr)
		}
	}

	return podSelector
}

// parseSelector translates a (namespaceSelector, podSelector) pair into a Cilium-native EndpointSelector.
// An optional namespace can be provided to evaluate the selectors within that namespace in case no
// namespaceSelector was provided:
//
//	namespaceSelector podSelector namespace  Outcome
//	----------------- ----------- ---------- -----------------------------------------------------------------------------
//	   Yes               Yes         -       Selects endpoints matching both the namespaceSelector and podSelector
//	   Yes               No          -       Selects all endpoints within all namespaces selected by the namespaceSelector
//	   No                Yes         Yes     Selects endpoints matching the podSelector within the provided namespace
//	   No                Yes         No      Selects endpoints matching the podSelector in all namespaces*
//	   No                No          Yes     Selects all endpoints within the provided namespace
//	   No                No          No      Selects all endpoints in all namespaces*
//
// Note: Cases marked with an asterisks (*) are currently disallowed by IsovalentClusterwideEncryptionPolicy,
// but may be supported in the future, which is why this function already supports and tests it.
func parseSelector(namespace string, namespaceSelectorIn, podSelectorIn *slim_metav1.LabelSelector) api.EndpointSelector {
	if namespaceSelectorIn != nil {
		// Namespace selector provided. Translate it into a Cilium label selector and
		// combine it with the optional pod selector
		namespaceSelector := &slim_metav1.LabelSelector{
			MatchLabels: make(map[string]string, len(namespaceSelectorIn.MatchLabels)),
		}
		// We use our own special label prefix for namespace metadata,
		// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
		for k, v := range namespaceSelectorIn.MatchLabels {
			namespaceSelector.MatchLabels[networkPolicy.JoinPath(k8sConst.PodNamespaceMetaLabels, k)] = v
		}

		// We use our own special label prefix for namespace metadata,
		// thus we need to prefix that prefix to all NamespaceSelector.MatchExpressions
		for _, matchExp := range namespaceSelectorIn.MatchExpressions {
			lsr := slim_metav1.LabelSelectorRequirement{
				Key:      networkPolicy.JoinPath(k8sConst.PodNamespaceMetaLabels, matchExp.Key),
				Operator: matchExp.Operator,
				Values:   slices.Clone(matchExp.Values),
			}
			namespaceSelector.MatchExpressions = append(namespaceSelector.MatchExpressions, lsr)
		}

		// Empty namespace selector selects all namespaces (i.e., a namespace label exists).
		if len(namespaceSelector.MatchLabels) == 0 && len(namespaceSelector.MatchExpressions) == 0 {
			namespaceSelector.MatchExpressions = []slim_metav1.LabelSelectorRequirement{allowAllNamespacesRequirement}
		}

		// Combine translated namespaceSelector with provided podSelector
		return api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, namespaceSelector, podSelectorIn)
	} else if podSelectorIn != nil {
		// Only a podSelector was provided. Make sure it only matches in the current namespace
		podSelector := parsePodSelector(namespace, podSelectorIn)
		return api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, podSelector)
	} else if namespace != "" {
		// Empty selector on namespaced resource. Make sure we only select endpoints in current namespace
		podSelector := &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
			k8sConst.PodNamespaceLabel: namespace,
		}}
		return api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, podSelector)
	}

	// Empty podSelector on non-namespaced resource selects all endpoints
	return api.WildcardEndpointSelector
}

// parseEncryptionPolicy translates an IsovalentClusterwideEncryptionPolicy spec into a list parsedSelectorTuple structs.
// It basically performs the following transformation:
//
//	(subjectSelector, [(peerSelector, peerPorts)]) -> [(subjectSelector, peerSelector, peerPorts)]
//
// It also translates the subject and peer K8s label selectors into Cilium-native endpoint selectors and parses and
// validates the provided port list.
func parseEncryptionPolicy(resourceKey resource.Key, spec iso_v1alpha1.ClusterwideEncryptionPolicySpec) ([]parsedSelectorRule, error) {
	switch {
	case spec.NamespaceSelector == nil:
		return nil, fmt.Errorf("missing namespaceSelector in resource %q", resourceKey.String())
	case len(spec.Peers) == 0:
		return nil, fmt.Errorf("missing peers in resource %q", resourceKey.String())
	}

	tuples := make([]parsedSelectorRule, 0, len(spec.Peers))
	subjectEndpointSelector := parseSelector(resourceKey.Namespace, spec.NamespaceSelector, spec.PodSelector)
	for idx, peer := range spec.Peers {
		switch {
		case peer.NamespaceSelector == nil:
			return nil, fmt.Errorf("missing namespaceSelector for peer %d in resource %q", idx, resourceKey.String())
		case len(peer.Ports) == 0:
			return nil, fmt.Errorf("missing ports for peer %d in resource %q", idx, resourceKey.String())
		}

		peerEndpointSelector := parseSelector(resourceKey.Namespace, peer.NamespaceSelector, peer.PodSelector)
		peerPorts, err := parsePeerPorts(peer.Ports)
		if err != nil {
			return nil, fmt.Errorf("invalid port for peer %d in resource %q: %w", idx, resourceKey.String(), err)
		}

		tuples = append(tuples, parsedSelectorRule{
			subject:   policyTypes.NewLabelSelector(subjectEndpointSelector),
			peer:      policyTypes.NewLabelSelector(peerEndpointSelector),
			peerPorts: peerPorts,
		})
	}

	return tuples, nil
}
