// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bgpv2

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func (m *BGPResourceMapper) reconcileClusterConfigs(ctx context.Context) error {
	clusterConfigs, err := m.clusterConfig.List()
	if err != nil {
		return err
	}

	for _, clusterConfig := range clusterConfigs {
		err = errors.Join(err, m.reconcileClusterConfig(ctx, clusterConfig))
	}
	return err
}

func (m *BGPResourceMapper) reconcileClusterConfig(ctx context.Context, config *v1alpha1.IsovalentBGPClusterConfig) error {
	// get nodes which match node selector for given cluster config
	matchingNodes, conflictingClusterConfigs, err := m.getMatchingNodes(config)
	if err != nil {
		return err
	}

	// update node configs for matched nodes
	for nodeRef := range matchingNodes {
		upsertErr := m.upsertNodeConfig(ctx, config, nodeRef)
		if upsertErr != nil {
			err = errors.Join(err, upsertErr)
		}
	}

	// delete node configs for this cluster that are not in the matching nodes
	dErr := m.deleteStaleNodeConfigs(ctx, matchingNodes, config)
	if dErr != nil {
		err = errors.Join(err, dErr)
	}

	// Collect the missing peerConfig references
	missingPCs := m.missingPeerConfigs(config)

	// Update ClusterConfig conditions
	updateStatus := false
	if changed := m.updateNoMatchingNodeCondition(config, len(matchingNodes) == 0); changed {
		updateStatus = true
	}
	if changed := m.updateMissingPeerConfigsCondition(config, missingPCs); changed {
		updateStatus = true
	}
	if changed := m.updateConflictingClusterConfigsCondition(config, conflictingClusterConfigs); changed {
		updateStatus = true
	}

	// validate VRFs and VRFConfigs if SRv6 is enabled
	if m.dc.EnableSRv6 {
		missingVRFs := m.missingVRFs(config)
		missingVRFConfigs := m.missingVRFConfigs(config)

		if changed := m.updateMissingVRFsCondition(config, missingVRFs); changed {
			updateStatus = true
		}

		if changed := m.updateMissingVRFConfigsCondition(config, missingVRFConfigs); changed {
			updateStatus = true
		}
	}

	// Sort conditions to the stable order
	slices.SortStableFunc(config.Status.Conditions, func(a, b meta_v1.Condition) int {
		return strings.Compare(a.Type, b.Type)
	})

	// Call API only when there's a condition change
	if updateStatus {
		_, uErr := m.clientSet.IsovalentV1alpha1().IsovalentBGPClusterConfigs().UpdateStatus(ctx, config, meta_v1.UpdateOptions{})
		if uErr != nil {
			err = errors.Join(err, uErr)
		}
	}

	return err
}

// missingPeerConfigs returns a IsovalentBGPPeerConfig which is referenced from
// the ClusterConfig, but doesn't exist. The returned slice is sorted and
// deduplicated for output stability.
func (m *BGPResourceMapper) missingPeerConfigs(config *v1alpha1.IsovalentBGPClusterConfig) []string {
	missing := []string{}
	for _, instance := range config.Spec.BGPInstances {
		for _, peer := range instance.Peers {
			if peer.PeerConfigRef == nil {
				continue
			}

			_, exists, _ := m.peerConfig.GetByKey(resource.Key{Name: peer.PeerConfigRef.Name})
			if !exists {
				missing = append(missing, peer.PeerConfigRef.Name)
			}

			// Just ignore the error other than NotFound. It might
			// be a network issue, or something else, but we are
			// only interested in detecting the invalid reference
			// here.
		}
	}
	slices.Sort(missing)
	return slices.Compact(missing)
}

// missingVRFs returns a IsovalentVRF which is referenced from
// the ClusterConfig, but doesn't exist. The returned slice is sorted and
// deduplicated for output stability.
func (m *BGPResourceMapper) missingVRFs(config *v1alpha1.IsovalentBGPClusterConfig) []string {
	missing := []string{}
	for _, instance := range config.Spec.BGPInstances {
		for _, vrf := range instance.VRFs {
			_, exists, _ := m.vrf.GetByKey(resource.Key{Name: vrf.VRFRef})
			if !exists {
				missing = append(missing, vrf.VRFRef)
			}
		}
	}
	slices.Sort(missing)
	return slices.Compact(missing)
}

// missingVRFConfigs returns a IsovalentBGPVRFConfig which is referenced from
// the ClusterConfig, but doesn't exist. The returned slice is sorted and
// deduplicated for output stability.
func (m *BGPResourceMapper) missingVRFConfigs(config *v1alpha1.IsovalentBGPClusterConfig) []string {
	missing := []string{}
	for _, instance := range config.Spec.BGPInstances {
		for _, vrf := range instance.VRFs {
			if vrf.ConfigRef == nil {
				continue
			}
			_, exists, _ := m.vrfConfig.GetByKey(resource.Key{Name: *vrf.ConfigRef})
			if !exists {
				missing = append(missing, *vrf.ConfigRef)
			}
		}
	}
	slices.Sort(missing)
	return slices.Compact(missing)
}

func (m *BGPResourceMapper) updateConflictingClusterConfigsCondition(config *v1alpha1.IsovalentBGPClusterConfig, conflictingClusterConfigs sets.Set[string]) bool {
	cond := meta_v1.Condition{
		Type:               v1alpha1.BGPClusterConfigConditionConflictingClusterConfigs,
		Status:             meta_v1.ConditionFalse,
		ObservedGeneration: config.Generation,
		LastTransitionTime: meta_v1.Now(),
		Reason:             "ConflictingClusterConfigs",
	}
	if conflictingClusterConfigs.Len() != 0 {
		cond.Status = meta_v1.ConditionTrue
		cond.Message = fmt.Sprintf("Selecting the same node(s) with ClusterConfig(s): %v", sets.List(conflictingClusterConfigs))
	}
	return meta.SetStatusCondition(&config.Status.Conditions, cond)
}

func (m *BGPResourceMapper) updateMissingPeerConfigsCondition(config *v1alpha1.IsovalentBGPClusterConfig, missingPCs []string) bool {
	cond := meta_v1.Condition{
		Type:               v1alpha1.BGPClusterConfigConditionMissingPeerConfigs,
		Status:             meta_v1.ConditionFalse,
		ObservedGeneration: config.Generation,
		LastTransitionTime: meta_v1.Now(),
		Reason:             "MissingPeerConfigs",
	}
	if len(missingPCs) != 0 {
		cond.Status = meta_v1.ConditionTrue
		cond.Message = fmt.Sprintf("Referenced IsovalentBGPPeerConfig(s) are missing: %v", missingPCs)
	}
	return meta.SetStatusCondition(&config.Status.Conditions, cond)
}

func (m *BGPResourceMapper) updateNoMatchingNodeCondition(config *v1alpha1.IsovalentBGPClusterConfig, noMatchingNode bool) bool {
	cond := meta_v1.Condition{
		Type:               v1alpha1.BGPClusterConfigConditionNoMatchingNode,
		Status:             meta_v1.ConditionTrue,
		ObservedGeneration: config.Generation,
		LastTransitionTime: meta_v1.Now(),
		Reason:             "NoMatchingNode",
		Message:            "No node matches spec.nodeSelector",
	}
	if !noMatchingNode {
		cond.Status = meta_v1.ConditionFalse
	}
	return meta.SetStatusCondition(&config.Status.Conditions, cond)
}

func (m *BGPResourceMapper) updateMissingVRFsCondition(config *v1alpha1.IsovalentBGPClusterConfig, missingVRFs []string) bool {
	cond := meta_v1.Condition{
		Type:               v1alpha1.BGPClusterConfigConditionMissingVRFs,
		Status:             meta_v1.ConditionFalse,
		ObservedGeneration: config.Generation,
		LastTransitionTime: meta_v1.Now(),
		Reason:             "MissingVRF",
	}
	if len(missingVRFs) != 0 {
		cond.Status = meta_v1.ConditionTrue
		cond.Message = fmt.Sprintf("Referenced IsovalentVRF(s) are missing: %v", missingVRFs)
	}
	return meta.SetStatusCondition(&config.Status.Conditions, cond)
}

func (m *BGPResourceMapper) updateMissingVRFConfigsCondition(config *v1alpha1.IsovalentBGPClusterConfig, missingVRFConfigs []string) bool {
	cond := meta_v1.Condition{
		Type:               v1alpha1.BGPClusterConfigConditionMissingVRFConfigs,
		Status:             meta_v1.ConditionFalse,
		ObservedGeneration: config.Generation,
		LastTransitionTime: meta_v1.Now(),
		Reason:             "MissingBGPVRFConfig",
	}
	if len(missingVRFConfigs) != 0 {
		cond.Status = meta_v1.ConditionTrue
		cond.Message = fmt.Sprintf("Referenced IsovalentBGPVRFConfig(s) are missing: %v", missingVRFConfigs)
	}
	return meta.SetStatusCondition(&config.Status.Conditions, cond)
}

func (m *BGPResourceMapper) upsertNodeConfig(ctx context.Context, config *v1alpha1.IsovalentBGPClusterConfig, nodeName string) error {
	prev, exists, err := m.nodeConfigStore.GetByKey(resource.Key{Name: nodeName})
	if err != nil {
		return err
	}

	// find node override instances for given node
	var overrideInstances []v1alpha1.IsovalentBGPNodeConfigInstanceOverride
	override, overrideExists, err := m.nodeConfigOverride.GetByKey(resource.Key{Name: nodeName})
	if err != nil {
		return err
	}
	if overrideExists {
		overrideInstances = override.Spec.BGPInstances
	}

	// create new config
	nodeConfig := &v1alpha1.IsovalentBGPNodeConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: nodeName,
			OwnerReferences: []meta_v1.OwnerReference{
				{
					APIVersion: v1alpha1.SchemeGroupVersion.String(),
					Kind:       v1alpha1.IsovalentBGPClusterConfigKindDefinition,
					Name:       config.GetName(),
					UID:        config.GetUID(),
				},
			},
		},
		Spec: v1alpha1.IsovalentBGPNodeSpec{
			BGPInstances: toNodeBGPInstance(config.Spec.BGPInstances, overrideInstances),
		},
	}

	nodeConfigClient := m.clientSet.IsovalentV1alpha1().IsovalentBGPNodeConfigs()

	switch {
	case exists && prev.Spec.DeepEqual(&nodeConfig.Spec):
		return nil
	case exists:
		// reinitialize spec and status fields
		prev.Spec = nodeConfig.Spec
		_, err = nodeConfigClient.Update(ctx, prev, meta_v1.UpdateOptions{})
	default:
		_, err = nodeConfigClient.Create(ctx, nodeConfig, meta_v1.CreateOptions{})
	}

	m.logger.WithFields(logrus.Fields{
		"node config":    nodeConfig.Name,
		"cluster config": config.Name,
	}).Debug("Updating Isovalent BGP node config")

	return err
}

func toNodeBGPInstance(clusterBGPInstances []v1alpha1.IsovalentBGPInstance, overrideBGPInstances []v1alpha1.IsovalentBGPNodeConfigInstanceOverride) []v1alpha1.IsovalentBGPNodeInstance {
	var res []v1alpha1.IsovalentBGPNodeInstance

	for _, clusterBGPInstance := range clusterBGPInstances {
		nodeBGPInstance := v1alpha1.IsovalentBGPNodeInstance{
			Name:     clusterBGPInstance.Name,
			LocalASN: clusterBGPInstance.LocalASN,
		}

		// find BGPResourceManager global override for this instance
		var override v1alpha1.IsovalentBGPNodeConfigInstanceOverride
		for _, overrideBGPInstance := range overrideBGPInstances {
			if overrideBGPInstance.Name == clusterBGPInstance.Name {
				nodeBGPInstance.RouterID = overrideBGPInstance.RouterID
				nodeBGPInstance.LocalPort = overrideBGPInstance.LocalPort
				nodeBGPInstance.SRv6Responder = overrideBGPInstance.SRv6Responder
				override = overrideBGPInstance
				break
			}
		}

		for _, bgpInstancePeer := range clusterBGPInstance.Peers {
			nodePeer := v1alpha1.IsovalentBGPNodePeer{
				Name:          bgpInstancePeer.Name,
				PeerAddress:   bgpInstancePeer.PeerAddress,
				PeerASN:       bgpInstancePeer.PeerASN,
				Interface:     bgpInstancePeer.Interface,
				PeerConfigRef: bgpInstancePeer.PeerConfigRef,
			}

			// find BGPResourceManager Peer override for this instance
			for _, overrideBGPPeer := range override.Peers {
				if overrideBGPPeer.Name == bgpInstancePeer.Name {
					nodePeer.Interface = overrideBGPPeer.Interface
					nodePeer.LocalAddress = overrideBGPPeer.LocalAddress
					break
				}
			}

			nodeBGPInstance.Peers = append(nodeBGPInstance.Peers, nodePeer)
		}

		for _, bgpVRF := range clusterBGPInstance.VRFs {
			nodeBGPInstance.VRFs = append(nodeBGPInstance.VRFs, v1alpha1.IsovalentBGPNodeVRF(bgpVRF))
		}

		res = append(res, nodeBGPInstance)
	}
	return res
}

// deleteStaleNodeConfigs deletes node configs that are not in the expected list for given cluster.
func (m *BGPResourceMapper) deleteStaleNodeConfigs(ctx context.Context, expectedNodes sets.Set[string], config *v1alpha1.IsovalentBGPClusterConfig) (err error) {
	for _, existingNode := range m.nodeConfigStore.List() {
		if expectedNodes.Has(existingNode.Name) || !isOwner(existingNode.GetOwnerReferences(), config) {
			continue
		}

		dErr := m.clientSet.IsovalentV1alpha1().IsovalentBGPNodeConfigs().Delete(ctx, existingNode.Name, meta_v1.DeleteOptions{})
		if dErr != nil && k8s_errors.IsNotFound(dErr) {
			continue
		} else if dErr != nil {
			err = errors.Join(err, dErr)
		} else {
			m.logger.WithFields(logrus.Fields{
				"node_config":    existingNode.Name,
				"cluster_config": config.Name,
			}).Debug("Deleting Isovalent BGP node config")
		}
	}
	return err
}

// getMatchingNodes returns a map of node names that match the given cluster config's node selector.
func (m *BGPResourceMapper) getMatchingNodes(config *v1alpha1.IsovalentBGPClusterConfig) (sets.Set[string], sets.Set[string], error) {
	labelSelector, err := slim_meta_v1.LabelSelectorAsSelector(config.Spec.NodeSelector)
	if err != nil {
		return nil, nil, err
	}

	// find nodes that match the cluster config's node selector
	matchingNodes := sets.New[string]()

	// find ClusterConfigs that has the conflicting node selector
	conflictingClusterConfigs := sets.New[string]()

	ciliumNodes, err := m.ciliumNode.List()
	if err != nil {
		return nil, nil, err
	}

	for _, n := range ciliumNodes {
		// nil node selector means match all nodes
		if config.Spec.NodeSelector == nil || labelSelector.Matches(slim_labels.Set(n.Labels)) {
			nc, exists, err := m.nodeConfigStore.GetByKey(resource.Key{Name: n.Name})
			if err != nil {
				m.logger.WithError(err).Errorf("skipping node %s", n.Name)
				continue
			}

			if exists && !isOwner(nc.GetOwnerReferences(), config) {
				// Node is already selected by another cluster config. Figure out which one.
				ownerName := ownerClusterConfigName(nc.GetOwnerReferences())
				conflictingClusterConfigs.Insert(ownerName)
				continue
			}

			matchingNodes.Insert(n.Name)
		}
	}

	return matchingNodes, conflictingClusterConfigs, nil
}

// isOwner checks if the expected is present in owners list.
func isOwner(owners []meta_v1.OwnerReference, config *v1alpha1.IsovalentBGPClusterConfig) bool {
	for _, owner := range owners {
		if owner.UID == config.GetUID() {
			return true
		}
	}
	return false
}

// ownerClusterConfigName returns the name of the ClusterConfig that owns the object
func ownerClusterConfigName(owners []meta_v1.OwnerReference) string {
	for _, owner := range owners {
		if owner.APIVersion == v1alpha1.SchemeGroupVersion.String() && owner.Kind == v1alpha1.IsovalentBGPClusterConfigKindDefinition {
			return owner.Name
		}
	}
	return ""
}
