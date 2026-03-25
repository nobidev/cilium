// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vrf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	dpTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/k8s/client"
	slimLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/cilium/cilium/pkg/endpointmanager"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/vrf/config"
)

// CiliumVRFDevicePrefix is the prefix used for naming VRF devices created by this controller.
const CiliumVRFDevicePrefix = "cvrf-"

// CiliumVRFDeviceFMT is the format string used to generate VRF device names, where the VRF's table ID is substituted in.
const CiliumVRFDeviceFMT = CiliumVRFDevicePrefix + "%d"

// Attempt a reconcilization every 30 seconds.
//
// This allows VRFs which suffered from transient netlink errors to reconcile
// without requiring a Device or VRF stateDB event.
const reconcileInterval = 30 * time.Second

type controllerParams struct {
	cell.In

	Config         config.Config
	Logger         *slog.Logger
	DB             *statedb.DB
	JobGroup       job.Group
	Clientset      client.Clientset
	Endpoints      endpointmanager.EndpointsLookup
	LocalNodeStore *node.LocalNodeStore
	LocalNodes     statedb.Table[*node.LocalNode]
	VRFs           statedb.Table[VRF]
	Devices        statedb.Table[*dpTables.Device]
}

type controller struct {
	logger         *slog.Logger
	db             *statedb.DB
	clientset      client.Clientset
	endpoints      endpointmanager.EndpointsLookup
	localNodeStore *node.LocalNodeStore
	localNodes     statedb.Table[*node.LocalNode]
	vrfs           statedb.Table[VRF]
	devices        statedb.Table[*dpTables.Device]

	nodeName        string
	active          map[string]*VRF
	activeByID      map[uint64]*VRF
	activeByTableID map[int32]*VRF
}

func registerController(p controllerParams) {
	if !p.Config.EnableVRF {
		return
	}
	c := &controller{
		logger:          p.Logger,
		db:              p.DB,
		clientset:       p.Clientset,
		endpoints:       p.Endpoints,
		localNodeStore:  p.LocalNodeStore,
		localNodes:      p.LocalNodes,
		vrfs:            p.VRFs,
		devices:         p.Devices,
		active:          make(map[string]*VRF),
		activeByID:      make(map[uint64]*VRF),
		activeByTableID: make(map[int32]*VRF),
	}
	p.JobGroup.Add(job.OneShot("vrf-controller", c.run))
}

// updateNodeVRFStatus performs a read-modify-write on the CiliumNode's VRF
// status with retry on conflict. The mutate function receives the current VRF
// status map and should modify it in place.
func (c *controller) updateNodeVRFStatus(ctx context.Context, update func(map[string]ciliumv2.VRFNodeStatus)) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		ciliumNode, err := c.clientset.CiliumV2().CiliumNodes().Get(ctx, c.nodeName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get CiliumNode %q: %w", c.nodeName, err)
		}

		if ciliumNode.Status.VRF == nil {
			ciliumNode.Status.VRF = make(map[string]ciliumv2.VRFNodeStatus)
		}

		update(ciliumNode.Status.VRF)

		if len(ciliumNode.Status.VRF) == 0 {
			ciliumNode.Status.VRF = nil
		}

		_, err = c.clientset.CiliumV2().CiliumNodes().UpdateStatus(ctx, ciliumNode, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update CiliumNode %q VRF status: %w", c.nodeName, err)
		}
		return nil
	})
}

// setVRFStatus updates the VRF status conditions on this node.
//
// When ready is false, a single error condition is set indicating why the VRF
// cannot be reconciled, and VRFConditionReady is set to false.
//
// When ready is true, all error conditions are cleared and VRFConditionReady
// is set to true.
func (c *controller) setVRFStatus(ctx context.Context, vrfName string, condition string, ready bool, message string) error {
	return c.updateNodeVRFStatus(ctx, func(vrfStatuses map[string]ciliumv2.VRFNodeStatus) {
		vrfStatus := vrfStatuses[vrfName]

		if ready {
			meta.RemoveStatusCondition(&vrfStatus.Conditions, ciliumv2.VRFConditionInterfaceNotFound)
			meta.RemoveStatusCondition(&vrfStatus.Conditions, ciliumv2.VRFConditionConflictingTableID)
			meta.RemoveStatusCondition(&vrfStatus.Conditions, ciliumv2.VRFConditionConflictingID)
			meta.RemoveStatusCondition(&vrfStatus.Conditions, ciliumv2.VRFConditionInterfaceFailure)
			meta.RemoveStatusCondition(&vrfStatus.Conditions, ciliumv2.VRFConditionUpdateFailure)

			meta.SetStatusCondition(&vrfStatus.Conditions, metav1.Condition{
				Type:    ciliumv2.VRFConditionReady,
				Status:  metav1.ConditionTrue,
				Reason:  "Active",
				Message: message,
			})
		} else {
			// Clear all prior error conditions so only the current
			// failure reason is reported.
			meta.RemoveStatusCondition(&vrfStatus.Conditions, ciliumv2.VRFConditionInterfaceNotFound)
			meta.RemoveStatusCondition(&vrfStatus.Conditions, ciliumv2.VRFConditionConflictingTableID)
			meta.RemoveStatusCondition(&vrfStatus.Conditions, ciliumv2.VRFConditionConflictingID)
			meta.RemoveStatusCondition(&vrfStatus.Conditions, ciliumv2.VRFConditionInterfaceFailure)
			meta.RemoveStatusCondition(&vrfStatus.Conditions, ciliumv2.VRFConditionUpdateFailure)

			meta.SetStatusCondition(&vrfStatus.Conditions, metav1.Condition{
				Type:    condition,
				Status:  metav1.ConditionTrue,
				Reason:  "Pending",
				Message: message,
			})
			meta.SetStatusCondition(&vrfStatus.Conditions, metav1.Condition{
				Type:    ciliumv2.VRFConditionReady,
				Status:  metav1.ConditionFalse,
				Reason:  "Pending",
				Message: message,
			})
		}

		vrfStatuses[vrfName] = vrfStatus
	})
}

// clearVRFStatus removes a VRF's status entry from this node.
func (c *controller) clearVRFStatus(ctx context.Context, vrfName string) error {
	return c.updateNodeVRFStatus(ctx, func(vrfStatuses map[string]ciliumv2.VRFNodeStatus) {
		delete(vrfStatuses, vrfName)
	})
}

// endpointPodLabels returns the pod labels for the given endpoint. If the
// endpoint's cached pod has no labels, it falls back to fetching from the API
// server.
func (c *controller) endpointPodLabels(ctx context.Context, ep *endpoint.Endpoint) (slimLabels.Set, bool) {
	pod := ep.GetPod()
	if pod != nil && pod.Labels != nil {
		return pod.Labels, true
	}
	// this should really not happen, since PodNames are restored from disk
	// on restart, but in the event that for some reason a label selector matches
	// an endpoint with no Pod name, we'll bail out here.
	if ep.GetK8sNamespace() == "" || ep.GetK8sPodName() == "" {
		return nil, false
	}
	k8sPod, err := c.clientset.CoreV1().Pods(ep.GetK8sNamespace()).Get(ctx, ep.GetK8sPodName(), metav1.GetOptions{})
	if err != nil {
		c.logger.Warn("Failed to fetch pod labels from API server", logfields.EndpointID, ep.GetID(), logfields.Error, err)
		return nil, false
	}
	return k8sPod.Labels, true
}

// matchesEndpoint returns true if the endpoint's pod and namespace labels match
// the VRF's selectors. At least one selector must be set for a match.
func (c *controller) matchesEndpoint(ctx context.Context, rc *reconcileCache, vrf *VRF, ep *endpoint.Endpoint) bool {
	nsSel := vrf.namespaceSelector()
	if nsSel != nil {
		nsLabels, ok := rc.namespaceLabels(ep.GetK8sNamespace())
		if !ok {
			return false
		}
		if !nsSel.Matches(slimLabels.Set(nsLabels)) {
			return false
		}
	}

	podSel := vrf.selector()
	if podSel != nil {
		podLabels, ok := c.endpointPodLabels(ctx, ep)
		if !ok {
			return false
		}
		if !podSel.Matches(podLabels) {
			return false
		}
	}

	return nsSel != nil || podSel != nil
}

// regenerateEndpoints triggers a datapath regeneration for all local endpoints
// whose pods match the given VRF's selectors.
//
// The tableID is passed in explicitly, as opposed to being supplied by the VRF
// in the scenario where the provided VRF is used to select pods which need to be
// moved back to the default VRF of 0.
func (c *controller) regenerateEndpoints(ctx context.Context, rc *reconcileCache, vrf *VRF, tableID uint32, reason string) {
	for _, ep := range c.endpoints.GetEndpoints() {
		if c.matchesEndpoint(ctx, rc, vrf, ep) {
			c.logger.Debug("Regenerating endpoint for VRF change", logfields.EndpointID, ep.GetID(), fieldVRF, vrf.Name)

			ep.SetFibTableID(tableID)
			ep.RegenerateIfAlive(&regeneration.ExternalRegenerationMetadata{
				Reason:            reason,
				RegenerationLevel: regeneration.RegenerateWithDatapath,
			})
		}
	}
}

// createVRF device will create a linux VRF device bound to the VRF's table ID
// and set the VRF's interfaces and children.
//
// It's expected that all interfaces have been deemed present on the host prior
// to invoking this function.
func (c *controller) createVRFDevice(ctx context.Context, vrf *VRF, name string) error {
	vrfDev := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
		Table: uint32(vrf.Table),
	}

	if err := netlink.LinkAdd(vrfDev); err != nil {
		return fmt.Errorf("failed to create VRF device %s: %w", name, err)
	}

	rollback := false
	defer func() {
		// best effort cleanup, if we fail here, reconciliation will take care
		// of it.
		if rollback {
			netlink.LinkDel(vrfDev)
		}
	}()

	if err := netlink.LinkSetUp(vrfDev); err != nil {
		rollback = true
		return fmt.Errorf("failed to bring up VRF device %s: %w", name, err)
	}

	vrfLink, err := netlink.LinkByName(name)
	if err != nil {
		rollback = true
		return fmt.Errorf("failed to look up VRF device %s after creation: %w", name, err)
	}

	for _, iface := range vrf.Interfaces {
		child, err := netlink.LinkByName(iface)
		if err != nil {
			rollback = true
			return fmt.Errorf("failed to look up VRF child interface %s: %w", iface, err)
		}

		if err := netlink.LinkSetMaster(child, vrfLink); err != nil {
			rollback = true
			return fmt.Errorf("failed to enslave interface %s to VRF device %s: %w", iface, name, err)
		}
	}

	return nil
}

// indexActiveVRF will add an active VRF into the controller's indexes.
func (c *controller) indexActiveVRF(ctx context.Context, vrf *VRF) {
	c.active[vrf.Name] = vrf
	c.activeByID[vrf.ID] = vrf
	c.activeByTableID[int32(vrf.Table)] = vrf
}

func (c *controller) unindexActiveVRF(ctx context.Context, vrf *VRF) {
	delete(c.active, vrf.Name)
	delete(c.activeByID, vrf.ID)
	delete(c.activeByTableID, int32(vrf.Table))
}

// addVRF attempts to make a VRF active in Cilium's datpath.
//
// This function will create a Linux VRF device associated with the VRF's table.
//
// The interfaces defined in the VRF will be become children of the VRF device,
// informing the kernel that traffic over those interfaces belong to the VRF.
//
// If no errors are encountered the VRF will be added to the c.active queue.
func (c *controller) addVRF(ctx context.Context, rc *reconcileCache, rtxn statedb.ReadTxn, vrf *VRF) error {
	// If this VRF's table ID conflicts with another, we must reject the add.
	if existing, ok := c.activeByTableID[int32(vrf.Table)]; ok {
		msg := fmt.Sprintf("VRF %q has conflicting table ID with active VRF %q", vrf.Name, existing.Name)
		if err := c.setVRFStatus(ctx, vrf.Name, ciliumv2.VRFConditionConflictingTableID, false, msg); err != nil {
			c.logger.Warn("Failed to set VRF status", fieldVRF, vrf.Name, logfields.Error, err)
		}
		return fmt.Errorf(msg)
	}

	// If this VRF's ID conflicts with another, we must reject the add.
	if existing, ok := c.activeByID[vrf.ID]; ok {
		msg := fmt.Sprintf("VRF %q has conflicting VRF ID with active VRF %q", vrf.Name, existing.Name)
		if err := c.setVRFStatus(ctx, vrf.Name, ciliumv2.VRFConditionConflictingID, false, msg); err != nil {
			c.logger.Warn("Failed to set VRF status", fieldVRF, vrf.Name, logfields.Error, err)
		}
		return fmt.Errorf(msg)
	}

	// ensure all required interfaces are present on host.
	for _, iface := range vrf.Interfaces {
		_, _, found := c.devices.Get(rtxn, dpTables.DeviceNameIndex.Query(iface))
		if !found {
			msg := fmt.Sprintf("interface %q not found for VRF %q", iface, vrf.Name)
			if err := c.setVRFStatus(ctx, vrf.Name, ciliumv2.VRFConditionInterfaceNotFound, false, msg); err != nil {
				c.logger.Warn("Failed to set VRF status", fieldVRF, vrf.Name, logfields.Error, err)
			}
			return fmt.Errorf(msg)
		}
	}

	// Determine if a VRF device with our naming scheme for this VRF exists
	vrfLinkName := fmt.Sprintf(CiliumVRFDeviceFMT, vrf.Table)
	if err := c.createVRFDevice(ctx, vrf, vrfLinkName); err != nil {
		msg := fmt.Sprintf("failed to create VRF device for VRF %q: %v", vrf.Name, err)
		if err := c.setVRFStatus(ctx, vrf.Name, ciliumv2.VRFConditionInterfaceFailure, false, msg); err != nil {
			c.logger.Warn("Failed to set VRF status", fieldVRF, vrf.Name, logfields.Error, err)
		}
		return fmt.Errorf(msg)
	}

	// the VRF device is now present and configured, we can consider the VRF
	// active, and add it to our indexes.
	c.indexActiveVRF(ctx, vrf)

	msg := fmt.Sprintf("vrf %s successfully created", vrf.Name)
	if err := c.setVRFStatus(ctx, vrf.Name, "", true, msg); err != nil {
		c.logger.Warn("Failed to set VRF status", fieldVRF, vrf.Name, logfields.Error, err)
	}
	c.logger.Info(msg)

	// regenerate required endpoints, so they are now part of VRF
	c.regenerateEndpoints(ctx, rc, vrf, uint32(vrf.Table), "VRF created")

	return nil
}

// removeVRF will remove the VRF device associated with the VRF, place any
// endpoints which were part of this VRF back into the default VRF, and
// finally removes the VRF from the controller's index.
func (c *controller) removeVRF(ctx context.Context, rc *reconcileCache, vrf *VRF) error {
	// regenerator VRF's endpoints to the table ID 0, this will indicate to
	// the datapath that no VRF should be used.
	c.regenerateEndpoints(ctx, rc, vrf, 0, "VRF removed")

	// remove associated link, this will unbind any children links automatically
	//
	// Be aware that removing a child from the VRF interface calls the kernel
	// function 'cycle_netdev' for the device. This results in a up/down cycling
	// on the interface.
	vrfLinkName := fmt.Sprintf(CiliumVRFDeviceFMT, vrf.Table)
	vrfLink, err := netlink.LinkByName(vrfLinkName)
	if err != nil && !errors.As(err, &netlink.LinkNotFoundError{}) {
		return fmt.Errorf("failed to look up VRF device for VRF %q during removal: %w", vrf.Name, err)
	}

	if vrfLink != nil {
		if err := netlink.LinkDel(vrfLink); err != nil {
			return fmt.Errorf("failed to delete VRF device %s: %w", vrfLinkName, err)
		}
	}

	// VRF successfully cleaned up, we can remove it form our indexes.
	c.unindexActiveVRF(ctx, vrf)

	if err := c.clearVRFStatus(ctx, vrf.Name); err != nil {
		c.logger.Warn("Failed to clear VRF status from CiliumNode", fieldVRF, vrf.Name, logfields.Error, err)
	}

	c.logger.Debug("VRF successfully removed", fieldVRF, vrf.Name)

	return nil
}

// updateVRF handles changes in an active VRF.
//
// This function is also crucial in the initialize and restore path used on
// agent restore.
//
// Because this function is used both for updating VRFs created during runtime
// and partial VRFs seeded during restore, we must ensure all aspects of a
// VRF are in sync with the kernel's state.
func (c *controller) updateVRF(ctx context.Context, rc *reconcileCache, vrf *VRF) error {
	oldVRF, ok := c.active[vrf.Name]
	if !ok {
		return fmt.Errorf("VRF %q is not active, cannot update", vrf.Name)
	}

	if oldVRF.ID != vrf.ID {
		// ensure ID is not active
		if existing, ok := c.activeByID[vrf.ID]; ok && existing.Name != vrf.Name {
			msg := fmt.Sprintf("VRF %q has conflicting VRF ID with active VRF %q", vrf.Name, existing.Name)
			if err := c.setVRFStatus(ctx, vrf.Name, ciliumv2.VRFConditionConflictingID, false, msg); err != nil {
				c.logger.Warn("Failed to set VRF status", fieldVRF, vrf.Name, logfields.Error, err)
			}
			return fmt.Errorf(msg)
		}

		// TODO write new ID -> table ID mapping to datapath
	}

	if oldVRF.Table != vrf.Table {
		// ensure new TableID is not already active
		if existing, ok := c.activeByTableID[int32(vrf.Table)]; ok && existing.Name != vrf.Name {
			msg := fmt.Sprintf("VRF %q has conflicting table ID with active VRF %q", vrf.Name, existing.Name)
			if err := c.setVRFStatus(ctx, vrf.Name, ciliumv2.VRFConditionConflictingTableID, false, msg); err != nil {
				c.logger.Warn("Failed to set VRF status", fieldVRF, vrf.Name, logfields.Error, err)
			}
			return fmt.Errorf(msg)
		}

		if err := c.removeVRF(ctx, rc, oldVRF); err != nil {
			msg := fmt.Sprintf("failed to remove old VRF %q during update: %v", oldVRF.Name, err)
			if err := c.setVRFStatus(ctx, vrf.Name, ciliumv2.VRFConditionUpdateFailure, false, msg); err != nil {
				c.logger.Warn("Failed to set VRF status", fieldVRF, vrf.Name, logfields.Error, err)
			}
			return fmt.Errorf(msg)
		}
		if err := c.addVRF(ctx, rc, c.db.ReadTxn(), vrf); err != nil {
			// addVRF already sets the specific error condition on the node status.
			return fmt.Errorf("failed to add new VRF %q during update: %w", vrf.Name, err)
		}

		return nil
	}

	// if namespace or pod selector changes, we need to regen the old matched
	// pods to the default VRF, and regen new pods to the new VRF. If oldVRF.ID
	// == 0, this is a restored VRF, and we can skip the former regen.
	if !oldVRF.Selector.DeepEqual(&vrf.Selector) {
		// Reset old matched endpoints back to default VRF, unless this is
		// a restored partial (ID == 0) where init already handled stale endpoints.
		if oldVRF.ID != 0 {
			c.regenerateEndpoints(ctx, rc, oldVRF, 0, "VRF selector changed, removing from VRF")
		}
		// Assign newly matched endpoints to this VRF
		c.regenerateEndpoints(ctx, rc, vrf, uint32(vrf.Table), "VRF selector changed, adding to VRF")
	}

	// if interfaces are not equal, we need to unbind the old interfaces and
	// rebind the new ones. We only need to do this for changed interfaces.
	if !slices.Equal(oldVRF.Interfaces, vrf.Interfaces) {
		vrfDevName := fmt.Sprintf(CiliumVRFDeviceFMT, vrf.Table)
		vrfLink, err := safenetlink.LinkByName(vrfDevName)
		if err != nil {
			return fmt.Errorf("failed to look up VRF device %s: %w", vrfDevName, err)
		}

		// unbind removed interfaces
		for _, iface := range oldVRF.Interfaces {
			if slices.Contains(vrf.Interfaces, iface) {
				continue
			}
			child, err := safenetlink.LinkByName(iface)
			if err != nil {
				return fmt.Errorf("failed to look up interface %s to unbind from %s: %w", iface, vrfDevName, err)
			}
			if err := netlink.LinkSetNoMaster(child); err != nil {
				return fmt.Errorf("failed to unbind interface %s from VRF %s: %w", iface, vrfDevName, err)
			}
		}

		// bind added interfaces
		for _, iface := range vrf.Interfaces {
			if slices.Contains(oldVRF.Interfaces, iface) {
				continue
			}
			child, err := safenetlink.LinkByName(iface)
			if err != nil {
				return fmt.Errorf("failed to look up interface %s to bind to %s: %w", iface, vrfDevName, err)
			}
			if err := netlink.LinkSetMaster(child, vrfLink); err != nil {
				return fmt.Errorf("failed to bind interface %s to VRF %s: %w", iface, vrfDevName, err)
			}
		}
	}

	c.indexActiveVRF(ctx, vrf)

	msg := fmt.Sprintf("vrf %s successfully updated", vrf.Name)
	if err := c.setVRFStatus(ctx, vrf.Name, "", true, msg); err != nil {
		c.logger.Warn("Failed to set VRF status", fieldVRF, vrf.Name, logfields.Error, err)
	}

	return nil
}

func (c *controller) reconcile(ctx context.Context, rc *reconcileCache, rtxn statedb.ReadTxn) error {
	localNode, err := c.localNodeStore.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get local node: %w", err)
	}

	allVRFs := statedb.Collect(c.vrfs.All(rtxn))

	// Filter to VRFs targeting this node.
	currentVRFs := allVRFs[:0]
	for _, vrf := range allVRFs {
		if vrf.MatchesNode(localNode.Labels) {
			currentVRFs = append(currentVRFs, vrf)
		}
	}

	// Mark all active VRFs for removal; we'll prune these out below.
	if rc.toRemove == nil {
		rc.toRemove = make(map[string]*VRF, len(c.active))
	}
	for name, vrf := range c.active {
		rc.toRemove[name] = vrf
	}

	for _, vrf := range currentVRFs {
		if active, ok := c.active[vrf.Name]; ok {
			delete(rc.toRemove, vrf.Name)
			if !active.Equal(&vrf) {
				rc.toUpdate = append(rc.toUpdate, &vrf)
			}
		} else {
			rc.toAdd = append(rc.toAdd, &vrf)
		}
	}

	c.logger.Debug("VRF reconciliation", fieldToAdd, len(rc.toAdd), fieldToRemove, len(rc.toRemove), fieldToUpdate, len(rc.toUpdate))

	// Process removes first to free table/VRF IDs before adds and updates.
	for _, vrf := range rc.toRemove {
		if err := c.removeVRF(ctx, rc, vrf); err != nil {
			c.logger.Error("Failed to remove VRF", fieldVRF, vrf.Name, logfields.Error, err)
		}
	}

	for _, vrf := range rc.toUpdate {
		if err := c.updateVRF(ctx, rc, vrf); err != nil {
			c.logger.Error("Failed to update VRF", fieldVRF, vrf.Name, logfields.Error, err)
		}
	}

	for _, vrf := range rc.toAdd {
		if err := c.addVRF(ctx, rc, rtxn, vrf); err != nil {
			c.logger.Error("Failed to add VRF", fieldVRF, vrf.Name, logfields.Error, err)
		}
	}

	return nil
}

func (c *controller) init(ctx context.Context, rc *reconcileCache) error {
	// wait for VRF table sync.
	rtxn := c.db.ReadTxn()
	if initialized, watch := c.vrfs.Initialized(rtxn); !initialized {
		c.logger.Info("Waiting for CiliumVRF table to initialize before restore")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watch:
		}
	}

	// get VRFs that apply to this node
	rtxn = c.db.ReadTxn()
	localNode, err := c.localNodeStore.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get local node during restore: %w", err)
	}

	allVRFsForNodeByTable := map[int32]*VRF{}
	for vrf := range c.vrfs.All(rtxn) {
		if vrf.MatchesNode(localNode.Labels) {
			allVRFsForNodeByTable[vrf.Table] = &vrf
		}
	}

	// get list of cilium created VRF interfaces
	links, err := safenetlink.LinkList()
	if err != nil {
		return fmt.Errorf("failed to list links during restore: %w", err)
	}

	ciliumVRFDevicesByTable := map[int32]netlink.Link{}
	restorableVRFsByTable := map[int32]*VRF{}

	for _, link := range links {
		name := link.Attrs().Name
		if !strings.HasPrefix(name, CiliumVRFDevicePrefix) {
			continue
		}

		var tableID int32
		if _, err := fmt.Sscanf(name, CiliumVRFDeviceFMT, &tableID); err != nil {
			c.logger.Warn("Failed to parse table ID from VRF device name", fieldVRFDevice, name, logfields.Error, err)
			continue
		}

		ciliumVRFDevicesByTable[tableID] = link

		// if a cilium VRF device matches a VRF being applied to this node,
		// we can restore it on next reconcile.
		if vrf, ok := allVRFsForNodeByTable[tableID]; ok {
			restorableVRFsByTable[tableID] = vrf
		}
	}

	// remove all invalid interfaces
	for tableID, link := range ciliumVRFDevicesByTable {
		if _, ok := restorableVRFsByTable[tableID]; !ok {
			c.logger.Info("Removing orphaned VRF device", fieldVRFDevice, link.Attrs().Name, fieldTable, tableID)
			if err := netlink.LinkDel(link); err != nil {
				c.logger.Warn("Failed to delete orphaned VRF device", fieldVRFDevice, link.Attrs().Name, logfields.Error, err)
			}
		}
	}

	// loop thorough endpoints, if either:
	// 1. the endpoint references an invalid table ID
	// 2. the endpoint's labels no longer match its associated valid VRF
	// regenerate the endpoint back to the default VRF
	for _, ep := range c.endpoints.GetEndpoints() {
		fibID := ep.GetFibTableID()
		if fibID == 0 {
			continue
		}
		vrf, ok := restorableVRFsByTable[int32(fibID)]
		if !ok || !c.matchesEndpoint(ctx, rc, vrf, ep) {
			c.logger.Info("Resetting stale fibTableID on endpoint",
				logfields.EndpointID, ep.GetID(), fieldTable, fibID)
			ep.SetFibTableID(0)
			ep.RegenerateIfAlive(&regeneration.ExternalRegenerationMetadata{
				Reason:            "VRF no longer applies to endpoint",
				RegenerationLevel: regeneration.RegenerateWithDatapath,
			})
			continue
		}
	}

	// restore partial VRF to active, next recooncile will perform an update
	// on this partial, and resolve it fully.
	for _, vrf := range restorableVRFsByTable {
		partial := VRF{
			// ID zero represents a restore, minimum ID via API is 1.
			ID:    0,
			Name:  vrf.Name,
			Table: vrf.Table,
		}

		// get names of interfaces enslaved to associated VRF device
		linkName := fmt.Sprintf(CiliumVRFDeviceFMT, vrf.Table)
		link, ok := ciliumVRFDevicesByTable[int32(vrf.Table)]
		if !ok {
			c.logger.Warn("Expected VRF device not found during restore", fieldVRFDevice, linkName)
			continue
		}

		for _, child := range links {
			if child.Attrs().MasterIndex == link.Attrs().Index {
				partial.Interfaces = append(partial.Interfaces, child.Attrs().Name)
			}
		}

		c.active[vrf.Name] = &partial
	}

	// clear VRF statuses, will be set on next reconcile, ensuring no stale
	// statuses are present.
	if err := c.updateNodeVRFStatus(ctx, func(vrfStatuses map[string]ciliumv2.VRFNodeStatus) {
		clear(vrfStatuses)
	}); err != nil {
		c.logger.Warn("Failed to clear VRF statuses during init", logfields.Error, err)
	}

	return nil
}

// Run starts our controller's reconcile loop.
func (c *controller) run(ctx context.Context, health cell.Health) error {
	c.logger.Info("Starting VRF controller")

	localNode, err := c.localNodeStore.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get local node: %w", err)
	}
	c.nodeName = localNode.Name

	var rc reconcileCache

	if err := rc.populateNamespaces(ctx, c.clientset); err != nil {
		return fmt.Errorf("failed to populate reconcile cache: %w", err)
	}

	// cleanup stale VRFs, regen endpoints in stale VRFs, and seed c.active
	// for updating restored VRFs.
	if err := c.init(ctx, &rc); err != nil {
		return fmt.Errorf("failed to initialize VRF controller: %w", err)
	}

	// Initial reconciliation to pick up any VRFs that were synced before
	// the controller started.
	c.reconcile(ctx, &rc, c.db.ReadTxn())

	retryTicker := time.NewTicker(reconcileInterval)
	defer retryTicker.Stop()

	for {
		// this ReadTxn is simply to get watches, we don't care about this
		// snapshot of the db.
		rtxn := c.db.ReadTxn()
		vrfsAll, vrfWatch := c.vrfs.AllWatch(rtxn)
		vrfs := statedb.Collect(vrfsAll)

		_, deviceWatch := c.devices.AllWatch(rtxn)
		_, _, nodeWatch, _ := c.localNodes.GetWatch(rtxn, node.LocalNodeQuery)

		select {
		case <-ctx.Done():
			return nil
		// watch for VRF changes
		case <-vrfWatch:
			c.logger.Debug("VRF change detected, reconciling")
		// watch for device changes, if a VRF is rejected due to an interface
		// in the VRF not being present, this event may reconcile the rejected
		// VRF.
		case <-deviceWatch:
			c.logger.Debug("Device change detected, reconciling")
		// watch for local node changes, if node labels change, a VRF may begin
		// to, or may no longer, apply to a node.
		case <-nodeWatch:
			c.logger.Debug("Local node change detected, reconciling")
		// a general reconciliation clock, this handles any transient errors,
		// such as netlink issues, that may have rejected a VRF at the time,
		// but has subsided.
		case <-retryTicker.C:
			if len(vrfs) == 0 && len(c.active) == 0 {
				continue
			}
			c.logger.Debug("Periodic VRF reconciliation")
		}
		rc.reset()
		if err := rc.populateNamespaces(ctx, c.clientset); err != nil {
			c.logger.Error("Failed to populate reconcile cache", logfields.Error, err)
			continue
		}
		// need a new ReadTxn to get snapshot which triggered the update.
		c.reconcile(ctx, &rc, c.db.ReadTxn())
	}
}
