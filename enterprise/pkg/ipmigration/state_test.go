//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ipmigration

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/require"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/api/v1/models"
)

func Test_endpointTemplates(t *testing.T) {
	uidPodA := k8sTypes.UID("5d8f216c-4faa-471b-88b3-94466ff51862")
	epA := &models.EndpointChangeRequest{
		Addressing: &models.AddressPair{
			IPV4:         "10.10.0.10",
			IPV4PoolName: "ip-10-10-0-10",
			IPV6:         "fd00::10",
			IPV6PoolName: "ip-fd00-10",
		},
		ContainerID:            "c1234",
		ContainerInterfaceName: "eth0",
		InterfaceName:          "veth_lxc_a",
		K8sNamespace:           "cilium-test",
		K8sPodName:             "pod-a",
		K8sUID:                 string(uidPodA),
	}

	uidPodB := k8sTypes.UID("0caeb7f7-2473-4f90-8754-df0c55aad6b6")
	epB1 := &models.EndpointChangeRequest{
		Addressing: &models.AddressPair{
			IPV4:         "10.10.0.20",
			IPV4PoolName: "ip-10-10-0-20",
			IPV6:         "fd00::20",
			IPV6PoolName: "ip-fd00-20",
		},
		ContainerID:            "c5678",
		ContainerInterfaceName: "eth0",
		InterfaceName:          "veth_lxc_b",
		K8sNamespace:           "cilium-test",
		K8sPodName:             "pod-b",
		K8sUID:                 string(uidPodB),
	}
	epB2 := &models.EndpointChangeRequest{
		Addressing: &models.AddressPair{
			IPV4:         "10.10.0.21",
			IPV4PoolName: "ip-10-10-0-21",
			IPV6:         "fd00::21",
			IPV6PoolName: "ip-fd00-21",
		},
		ContainerID:            "c5678",
		ContainerInterfaceName: "eth1",
		InterfaceName:          "veth_lxc_b2",
		K8sNamespace:           "cilium-test",
		K8sPodName:             "pod-b",
		K8sUID:                 string(uidPodB),
	}

	epC := &models.EndpointChangeRequest{
		ContainerID:            "c9012",
		ContainerInterfaceName: "eth0",
		InterfaceName:          "veth_lxc_c",
		DockerEndpointID:       "ep-c",
	}

	// New ephemeral endpoint template manager
	e := ephemeralEndpointTemplates()
	require.NotNil(t, e)

	// Store templates (one for pod a and two for pod b)
	err := e.persistEndpointTemplate(epA)
	require.NoError(t, err)
	err = e.persistEndpointTemplate(epB1)
	require.NoError(t, err)
	err = e.persistEndpointTemplate(epB2)
	require.NoError(t, err)

	// epC has no K8s UID, and thus should not be stored
	err = e.persistEndpointTemplate(epC)
	require.Error(t, err)

	// Look up epA
	epTmpl, err := e.getEndpointTemplatesForPod(uidPodA)
	require.NoError(t, err)
	require.Len(t, epTmpl, 1)
	require.Contains(t, epTmpl, epA)

	// Look up epB1
	epTmpl, err = e.getEndpointTemplatesForPod(uidPodB)
	require.NoError(t, err)
	require.Len(t, epTmpl, 2)
	require.Contains(t, epTmpl, epB1)
	require.Contains(t, epTmpl, epB2)

	// Delete epA template
	err = e.deleteEndpointTemplatesForPod(uidPodA)
	require.NoError(t, err)
	epTmpl, err = e.getEndpointTemplatesForPod(uidPodA)
	require.ErrorIs(t, err, fs.ErrNotExist)
	require.Empty(t, epTmpl)

	// Delete for non-existing UID is not an error
	err = e.deleteEndpointTemplatesForPod(uidPodA)
	require.NoError(t, err)

	// Reinsert epA
	err = e.persistEndpointTemplate(epA)
	require.NoError(t, err)

	// Reinsert epA again (insert for the same template should be idempotent)
	err = e.persistEndpointTemplate(epA)
	require.NoError(t, err)

	// Check there is exactly one template for pod A
	epTmpl, err = e.getEndpointTemplatesForPod(uidPodA)
	require.NoError(t, err)
	require.Len(t, epTmpl, 1)
	require.Contains(t, epTmpl, epA)

	// Prune epA, keep epB1 alive
	pruned, err := e.pruneEndpointTemplates(sets.Set[k8sTypes.UID]{
		uidPodB: struct{}{},
	})
	require.NoError(t, err)
	require.Equal(t, 1, pruned)

	// epA should still exist, but epB1 doesn't
	epTmpl, err = e.getEndpointTemplatesForPod(uidPodA)
	require.ErrorIs(t, err, fs.ErrNotExist)
	require.Empty(t, epTmpl)

	epTmpl, err = e.getEndpointTemplatesForPod(uidPodB)
	require.NoError(t, err)
	require.Len(t, epTmpl, 2)
	require.Contains(t, epTmpl, epB1)
	require.Contains(t, epTmpl, epB2)

	// Prune everything
	pruned, err = e.pruneEndpointTemplates(sets.Set[k8sTypes.UID]{})
	require.NoError(t, err)
	require.Equal(t, 1, pruned)

	epTmpl, err = e.getEndpointTemplatesForPod(uidPodB)
	require.ErrorIs(t, err, fs.ErrNotExist)
	require.Empty(t, epTmpl)
}
