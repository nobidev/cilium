// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package testutils

import (
	"fmt"
	"reflect"
	"strings"

	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	nadclientfake "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/fake"
	nadclientv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/testing"

	"github.com/cilium/cilium/pkg/k8s/testutils"
)

func init() {
	nadv1.AddToScheme(testutils.Scheme)
}

// NewFakeNADsClientset creates a new fake clientset for testing purposes. It extends
// the provided clientset to leverage the same underlying tracker, and performs the
// necessary adaptations due to NADs not following the canonical kind/resource mapping.
func NewFakeNADsClientset(fcs *FakeClientset) (*nadclientfake.Clientset, nadclientv1.K8sCniCncfIoV1Interface) {
	// We reuse the default tracker, rather than creating a separate one, as
	// otherwise objects created via k8s/add would end up into two trackers,
	// causing mismatches down the line.
	for _, tracker := range fcs.trackers {
		if tracker.domain != "*" {
			continue
		}

		var client = nadclientfake.NewSimpleClientset()
		prependReactors(client, tracker.tracker.(*statedbObjectTracker))

		// The NetworkAttachmentDefinitions kind is special, because the corresponding
		// plural name is network-attachment-definitions. However, this confuses our
		// tracker, which internally leverages the [meta.UnsafeGuessKindToResource]
		// heuristic. Hence, let's wrap the custom reactors configured above to tweak
		// the resource associated with the action, so that the heuristic is happy.
		client.ReactionChain[0] = reactor{client.ReactionChain[0]}
		client.WatchReactionChain[0] = watchReactor{client.WatchReactionChain[0]}

		return client, client.K8sCniCncfIoV1()
	}

	panic("could not find the default tracker")
}

type reactor struct{ r testing.Reactor }
type watchReactor struct{ r testing.WatchReactor }

func (r reactor) Handles(action testing.Action) bool {
	return r.r.Handles(stripDashesFromResourceAction(action))
}

func (r reactor) React(action testing.Action) (bool, runtime.Object, error) {
	return r.r.React(stripDashesFromResourceAction(action))
}

func (r watchReactor) Handles(action testing.Action) bool {
	return r.r.Handles(stripDashesFromResourceAction(action))
}

func (r watchReactor) React(action testing.Action) (bool, watch.Interface, error) {
	return r.r.React(stripDashesFromResourceAction(action))
}

// stripDashesFromResourceAction strips any dash from the resource name associated with
// the action. It works for any concrete action type embedding [testing.ActionImpl].
func stripDashesFromResourceAction(action testing.Action) testing.Action {
	v := reflect.ValueOf(action.DeepCopy())
	ptr := reflect.New(v.Type())
	ptr.Elem().Set(v)

	// ActionImpl embeds Resource schema.GroupVersionResource; navigate to its Resource string.
	gvr := ptr.Elem().FieldByName("Resource")
	if !gvr.IsValid() {
		panic(fmt.Sprintf("unsupported override for %T: no Resource field", action))
	}
	res := gvr.FieldByName("Resource")
	res.SetString(strings.ReplaceAll(res.String(), "-", ""))

	return ptr.Elem().Interface().(testing.Action)
}
