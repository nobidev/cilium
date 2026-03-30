//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package extlb

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBuildRestConfig_Kubeconfig(t *testing.T) {
	mgr := &remoteClusterManager{
		logger:   slog.New(slog.DiscardHandler),
		clusters: make(map[string]*remoteCluster),
	}

	// Create a valid kubeconfig
	kubeconfig := `
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJkakNDQVIyZ0F3SUJBZ0lCQURBS0JnZ3Foa2pPUFFRREFqQWpNU0V3SHdZRFZRUUREQmhyTTNNdGMyVnkKZG1WeUxXTmhRREUzTXpJMU5qSTJOelF3SGhjTk1qUXhNVEkyTURrd05EVTBXaGNOTXpReE1USTBNRGt3TkRVMApXakFqTVNFd0h3WURWUVFEREJock0zTXRjMlZ5ZG1WeUxXTmhRREUzTXpJMU5qSTJOelF3V1RBVEJnY3Foa2pPClBRSUJCZ2dxaGtqT1BRTUJCd05DQUFTcEdTSTd1clUvSFRJMUZwSDZ2RmoxL0s1NkhDSFZFRVZmV2NNWU1KeUIKRWxMWVJhMWh5Z3A1Tk10c0s5cUxqM0ZmaTRIZFF3bW11ZzU4eFY0OW9xL1BvMEl3UURBT0JnTlZIUThCQWY4RQpCQU1DQXFRd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBZEJnTlZIUTRFRmdRVUFPMWxJOTRXRTBJWG9iRG1BbWxsCjNuWTFLbXd3Q2dZSUtvWkl6ajBFQXdJRFJ3QXdSQUlnYTEydGNDRGFqQ0JDUDBEVkVSUWNVR3lJK2xqbkJ0Y2MKTFFKMUdUOWJqWm9DSUJhZUdJRlI5RW1YK3BKazBXNm1qMVRxVm1xRTJ5ZjdKbGg4c2llSVdkUzMKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
  name: default
contexts:
- context:
    cluster: default
    user: default
  name: default
current-context: default
users:
- name: default
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJrVENDQVRlZ0F3SUJBZ0lJYVpyMDd1NmVCT0F3Q2dZSUtvWkl6ajBFQXdJd0l6RWhNQjhHQTFVRUF3d1kKYXpOekxXTnNhV1Z1ZEMxallVQXhOek15TlRZeU5qYzBNQjRYRFRJME1URXlOakE1TURRMU5Gb1hEVEkxTVRFeQpOakE1TURRMU5Gb3dNREVYTUJVR0ExVUVDaE1PYzNsemRHVnRPbTFoYzNSbGNuTXhGVEFUQmdOVkJBTVRESE41CmMzUmxiVHBoWkcxcGJqQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJGTHhxSjFVdmtWaWZCQmcKTDVQQ29MNjVJNW9hbGx6M2l5WnIrME9BUFRXT3kzQ0VkN0RFdXdVaTBvaWVKWVc5cDh1NVA5ZitBaHI4R0VFSwpjMmpvRmxTalNEQkdNQTRHQTFVZER3RUIvd1FFQXdJRm9EQVRCZ05WSFNVRUREQUtCZ2dyQmdFRkJRY0RBakFmCkJnTlZIU01FR0RBV2dCUkduaTBnMklybFJhUEd4OUZRbm1sR2NLUDc3akFLQmdncWhrak9QUVFEQWdOSUFEQkYKQWlFQXFuMHcwZUg5WEF1OWVaK2JZSkNYYXMwY1V4aUhiYjJLa1lwUG9CQnRRbzBDSUJlTUJBemtCaTJhTHNJcApHMXBRNmZTQUlVeS9vN2pvT1MwbFF6NlNoMHJWCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJkakNDQVIyZ0F3SUJBZ0lCQURBS0JnZ3Foa2pPUFFRREFqQWpNU0V3SHdZRFZRUUREQmhyTTNNdFkyeHAKWlc1MExXTmhRREUzTXpJMU5qSTJOelF3SGhjTk1qUXhNVEkyTURrd05EVTBXaGNOTXpReE1USTBNRGt3TkRVMApXakFqTVNFd0h3WURWUVFEREJock0zTXRZMnhwWlc1MExXTmhRREUzTXpJMU5qSTJOelF3V1RBVEJnY3Foa2pPClBRSUJCZ2dxaGtqT1BRTUJCd05DQUFUbndvcnlQSkJVSlNncW9LZnlxWUhKenNOeHlZYWd6cml2azhGN1BoaWwKRVA1M0dVZGFTYVJCMFEvb0NBQjVVeXNHNHR3OHNnWG1GVCt1SjE2SVJ1cHlvMEl3UURBT0JnTlZIUThCQWY4RQpCQU1DQXFRd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBZEJnTlZIUTRFRmdRVVJwNHRJTmlLNVVXanhzZlJVSjVwClJuQ2orKzR3Q2dZSUtvWkl6ajBFQXdJRFJ3QXdSQUlnSjZjMndWRmVxb3JnM0FCcWwyYjlENGJtUkJvSlVGUGcKZ1RSOG1vb2I1cU1DSURaSkNPTVduTEtqVXhIajl5ajdqUVlFNk9jYnRpeWNJOGtIVUFSRnh5SnEKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
    client-key-data: LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IUUNBUUVFSUNsbEZ2ZXEvQWFFZmF2bnpuanRSRTJIcHVHWTlYdzZMSWZ0ckRITUxjRmpvQWNHQlN1QkJBQUsKb1VRRFFnQUVVdkdvblZTK1JXSjhFR0F2azhLZ3Zya2ptaHFXWFBlTEptdjdRNEE5Tlk3TGNJUjNzTVM3QlNMUwppSjRsaGIybnk3ay8xLzRDR3Z3WVFRcHphT2dXVkE9PQotLS0tLUVORCBFQyBQUklWQVRFIEtFWS0tLS0tCg==
`

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"kubeconfig": []byte(kubeconfig),
		},
	}

	config, err := mgr.buildRestConfig(secret)
	require.NoError(t, err)
	require.NotNil(t, config)
	require.Equal(t, "https://127.0.0.1:6443", config.Host)
}

func TestBuildRestConfig_MissingKubeconfig(t *testing.T) {
	mgr := &remoteClusterManager{
		logger:   slog.New(slog.DiscardHandler),
		clusters: make(map[string]*remoteCluster),
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{},
	}

	config, err := mgr.buildRestConfig(secret)
	require.Error(t, err)
	require.Nil(t, config)
	require.Contains(t, err.Error(), "secret must contain")
}

func TestNodeIPChanged(t *testing.T) {
	tests := []struct {
		name     string
		oldNode  *corev1.Node
		newNode  *corev1.Node
		expected bool
	}{
		{
			name: "no change - same IP",
			oldNode: &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
					},
				},
			},
			newNode: &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
					},
				},
			},
			expected: false,
		},
		{
			name: "IP changed",
			oldNode: &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
					},
				},
			},
			newNode: &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.0.0.2"},
					},
				},
			},
			expected: true,
		},
		{
			name: "IP added",
			oldNode: &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{},
				},
			},
			newNode: &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
					},
				},
			},
			expected: true,
		},
		{
			name: "IP removed",
			oldNode: &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
					},
				},
			},
			newNode: &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{},
				},
			},
			expected: true,
		},
		{
			name: "external IP changed but internal same",
			oldNode: &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
						{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
					},
				},
			},
			newNode: &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
						{Type: corev1.NodeExternalIP, Address: "5.6.7.8"},
					},
				},
			},
			expected: false,
		},
		{
			name: "no change - same IPv4 and IPv6",
			oldNode: &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
						{Type: corev1.NodeInternalIP, Address: "fd00::1"},
					},
				},
			},
			newNode: &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
						{Type: corev1.NodeInternalIP, Address: "fd00::1"},
					},
				},
			},
			expected: false,
		},
		{
			name: "IPv6 address changed",
			oldNode: &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
						{Type: corev1.NodeInternalIP, Address: "fd00::1"},
					},
				},
			},
			newNode: &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
						{Type: corev1.NodeInternalIP, Address: "fd00::2"},
					},
				},
			},
			expected: true,
		},
		{
			name: "IPv6 address added",
			oldNode: &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
					},
				},
			},
			newNode: &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
						{Type: corev1.NodeInternalIP, Address: "fd00::1"},
					},
				},
			},
			expected: true,
		},
		{
			name: "IPv6 address removed",
			oldNode: &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
						{Type: corev1.NodeInternalIP, Address: "fd00::1"},
					},
				},
			},
			newNode: &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := nodeIPChanged(tt.oldNode, tt.newNode)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestGetClient_ClusterNotFound(t *testing.T) {
	mgr := &remoteClusterManager{
		logger:   slog.New(slog.DiscardHandler),
		clusters: make(map[string]*remoteCluster),
	}

	client, err := mgr.GetClient("nonexistent-cluster")
	require.Error(t, err)
	require.Nil(t, client)
	require.Contains(t, err.Error(), "not found")
}

func TestStop_NonexistentCluster(t *testing.T) {
	mgr := &remoteClusterManager{
		logger:   slog.New(slog.DiscardHandler),
		clusters: make(map[string]*remoteCluster),
	}

	// Should not panic
	mgr.Stop("nonexistent-cluster")
}

func TestStop_ExistingCluster(t *testing.T) {
	mgr := &remoteClusterManager{
		logger:   slog.New(slog.DiscardHandler),
		clusters: make(map[string]*remoteCluster),
	}

	// Create a mock remote cluster
	cancelCalled := false
	informerStopClosed := false
	informerStop := make(chan struct{})

	mgr.clusters["test-cluster"] = &remoteCluster{
		name:         "test-cluster",
		cancel:       func() { cancelCalled = true },
		informerStop: informerStop,
	}

	// Start a goroutine to detect when informerStop is closed
	go func() {
		<-informerStop
		informerStopClosed = true
	}()

	mgr.Stop("test-cluster")

	require.True(t, cancelCalled)
	require.Eventually(t, func() bool { return informerStopClosed }, 100*1000000, 1000000) // 100ms timeout, 1ms poll
	require.NotContains(t, mgr.clusters, "test-cluster")
}

func TestStopAll(t *testing.T) {
	mgr := &remoteClusterManager{
		logger:   slog.New(slog.DiscardHandler),
		clusters: make(map[string]*remoteCluster),
	}

	cancelCount := 0
	mgr.clusters["cluster1"] = &remoteCluster{
		name:         "cluster1",
		cancel:       func() { cancelCount++ },
		informerStop: make(chan struct{}),
	}
	mgr.clusters["cluster2"] = &remoteCluster{
		name:         "cluster2",
		cancel:       func() { cancelCount++ },
		informerStop: make(chan struct{}),
	}

	err := mgr.StopAll()
	require.NoError(t, err)
	require.Equal(t, 2, cancelCount)
	require.Empty(t, mgr.clusters)
}

func TestSetServiceChangeCallback(t *testing.T) {
	mgr := &remoteClusterManager{
		logger:   slog.New(slog.DiscardHandler),
		clusters: make(map[string]*remoteCluster),
	}

	callbackInvoked := false
	var receivedClusterName string

	mgr.SetServiceChangeCallback(func(clusterName string) {
		callbackInvoked = true
		receivedClusterName = clusterName
	})

	// Trigger reconcile
	mgr.triggerReconcile("test-cluster")

	require.True(t, callbackInvoked)
	require.Equal(t, "test-cluster", receivedClusterName)
}
