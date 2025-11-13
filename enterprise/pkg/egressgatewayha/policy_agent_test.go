//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
)

func Test_updateMatchedEndpointIDs(t *testing.T) {
	// None matched, one added following update, should force update.
	pc := &AgentPolicyConfig{
		matchedEndpoints: map[endpointID]*endpointMetadata{},
		PolicyConfig: &PolicyConfig{
			endpointSelectors: []api.EndpointSelector{
				{
					LabelSelector: &slimv1.LabelSelector{
						MatchLabels: ep1Labels,
					},
				},
			},
		},
	}
	assert.True(t, pc.updateMatchedEndpointIDs(map[endpointID]*endpointMetadata{
		"ep1": {id: "ep1", labels: ep1Labels},
	}))

	assert.False(t, pc.updateMatchedEndpointIDs(map[endpointID]*endpointMetadata{
		"ep1": {id: "ep1", labels: ep1Labels},
	}))

	assert.True(t, pc.updateMatchedEndpointIDs(map[endpointID]*endpointMetadata{}))

	assert.True(t, pc.updateMatchedEndpointIDs(map[endpointID]*endpointMetadata{
		"ep1": {id: "ep1", labels: ep1Labels},
	}))

	// New matched ep
	assert.True(t, pc.updateMatchedEndpointIDs(map[endpointID]*endpointMetadata{
		"ep1": {id: "ep1", labels: ep1Labels},
		"ep2": {id: "ep2", labels: ep1Labels},
	}))

	assert.False(t, pc.updateMatchedEndpointIDs(map[endpointID]*endpointMetadata{
		"ep1": {id: "ep1", labels: ep1Labels},
		"ep2": {id: "ep2", labels: ep1Labels},
	}))
	assert.Equal(t, map[endpointID]*endpointMetadata{
		"ep1": {id: "ep1", labels: ep1Labels},
		"ep2": {id: "ep2", labels: ep1Labels},
	}, pc.matchedEndpoints)

	// New matched ep is no longer matched
	assert.True(t, pc.updateMatchedEndpointIDs(map[endpointID]*endpointMetadata{
		"ep1": {id: "ep1", labels: ep1Labels},
		"ep2": {id: "ep2", labels: ep2Labels},
	}))

	assert.Equal(t, map[endpointID]*endpointMetadata{
		"ep1": {id: "ep1", labels: ep1Labels},
	}, pc.matchedEndpoints)

	// Make ep2 matched agaikn
	assert.True(t, pc.updateMatchedEndpointIDs(map[endpointID]*endpointMetadata{
		"ep1": {id: "ep1", labels: ep1Labels},
		"ep2": {id: "ep2", labels: ep1Labels},
	}))
	assert.Equal(t, map[endpointID]*endpointMetadata{
		"ep1": {id: "ep1", labels: ep1Labels},
		"ep2": {id: "ep2", labels: ep1Labels},
	}, pc.matchedEndpoints)

	// Metadata change -> still need to update.
	lbls := maps.Clone(ep1Labels)
	lbls["foo"] = "bar"
	assert.True(t, pc.updateMatchedEndpointIDs(map[endpointID]*endpointMetadata{
		"ep1": {id: "ep1", labels: lbls},
		"ep2": {id: "ep2", labels: ep1Labels},
	}))
	assert.Equal(t, map[endpointID]*endpointMetadata{
		"ep1": {id: "ep1", labels: lbls},
		"ep2": {id: "ep2", labels: ep1Labels},
	}, pc.matchedEndpoints)
}
