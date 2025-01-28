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
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/statedb"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/api/v1/models"
	endpointrestapi "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	ipamrestapi "github.com/cilium/cilium/api/v1/server/restapi/ipam"
	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/pkg/endpointcreator"
	types "github.com/cilium/cilium/enterprise/pkg/ipmigration/types"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type mockEndpointMgr struct {
	id  *idpool.IDPool
	eps map[string][]*endpoint.Endpoint
}

func newMockEndpointMgr() *mockEndpointMgr {
	return &mockEndpointMgr{
		id:  idpool.NewIDPool(0, 4095),
		eps: make(map[string][]*endpoint.Endpoint),
	}
}

func (m *mockEndpointMgr) CreateEndpoint(ctx context.Context, epTemplate *models.EndpointChangeRequest) (*endpoint.Endpoint, error) {
	name := epTemplate.K8sNamespace + "/" + epTemplate.K8sPodName

	ep := &endpoint.Endpoint{
		ID:           uint16(m.id.AllocateID()),
		K8sPodName:   epTemplate.K8sPodName,
		K8sNamespace: epTemplate.K8sNamespace,
		K8sUID:       epTemplate.K8sUID,
	}

	if epTemplate.Addressing.IPV4 != "" {
		ep.IPv4 = netip.MustParseAddr(epTemplate.Addressing.IPV4)
		ep.IPv4IPAMPool = epTemplate.Addressing.IPV4PoolName
	}
	if epTemplate.Addressing.IPV6 != "" {
		ep.IPv6 = netip.MustParseAddr(epTemplate.Addressing.IPV6)
		ep.IPv6IPAMPool = epTemplate.Addressing.IPV6PoolName
	}

	m.eps[name] = append(m.eps[name], ep)
	return ep, nil
}

func (m *mockEndpointMgr) GetEndpointsByPodName(name string) []*endpoint.Endpoint {
	return m.eps[name]
}

func (m *mockEndpointMgr) RemoveEndpoint(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) []error {
	name := ep.K8sNamespace + "/" + ep.K8sPodName

	found := false
	m.eps[name] = slices.DeleteFunc(m.eps[name], func(e *endpoint.Endpoint) bool {
		if e.ID == ep.ID {
			found = true
			return true
		}
		return false
	})
	if !found {
		return []error{
			errors.New("endpoint not found"),
		}
	}

	return nil
}

func (m *mockEndpointMgr) Handle(p endpointrestapi.PutEndpointIDParams) middleware.Responder {
	ep, err := m.CreateEndpoint(context.TODO(), p.Endpoint)
	if err != nil {
		return endpointrestapi.NewPutEndpointIDFailed().WithPayload(models.Error(err.Error()))
	}

	return endpointrestapi.NewPutEndpointIDCreated().WithPayload(&models.Endpoint{
		ID: int64(ep.ID),
		Status: &models.EndpointStatus{
			Networking: &models.EndpointNetworking{
				Addressing:             []*models.AddressPair{p.Endpoint.Addressing},
				ContainerInterfaceName: p.Endpoint.ContainerInterfaceName,
				HostMac:                p.Endpoint.HostMac,
				InterfaceIndex:         p.Endpoint.InterfaceIndex,
				InterfaceName:          p.Endpoint.InterfaceName,
				Mac:                    p.Endpoint.Mac,
			},
			State: models.EndpointStateWaitingDashForDashIdentity.Pointer(),
		},
	})
}

type mockIPAMMetadata struct {
	db       *statedb.DB
	podTable statedb.Table[agentK8s.LocalPod]
}

func newMockIPAMMetadata(db *statedb.DB, podTable statedb.Table[agentK8s.LocalPod]) *mockIPAMMetadata {
	return &mockIPAMMetadata{db: db, podTable: podTable}
}

func (i *mockIPAMMetadata) GetIPPoolForPod(owner string, family ipam.Family) (pool string, err error) {
	namespace, name, ok := strings.Cut(owner, "/")
	if !ok {
		return ipam.PoolDefault().String(), nil
	}

	pod, _, ok := i.podTable.Get(i.db.ReadTxn(), agentK8s.PodByName(namespace, name))
	if !ok {
		return "", errors.New("pod not found")
	}

	if ipv4Pool, ok := pod.Annotations[annotation.IPAMIPv4PoolKey]; ok && family == ipam.IPv4 {
		return ipv4Pool, nil
	} else if ipv6Pool, ok := pod.Annotations[annotation.IPAMIPv6PoolKey]; ok && family == ipam.IPv6 {
		return ipv6Pool, nil
	} else if ipPool, ok := pod.Annotations[annotation.IPAMPoolKey]; ok {
		return ipPool, nil
	} else {
		return ipam.PoolDefault().String(), nil
	}
}

type mockIPAMAllocator struct {
	ips map[ipam.Pool]map[netip.Addr]string
}

func newMockIPAMAllocator() *mockIPAMAllocator {
	return &mockIPAMAllocator{
		ips: make(map[ipam.Pool]map[netip.Addr]string),
	}
}

func (m *mockIPAMAllocator) AllocateIP(ip net.IP, owner string, pool ipam.Pool) error {
	addr := netipx.MustFromStdIP(ip)
	if _, ok := m.ips[pool]; !ok {
		m.ips[pool] = make(map[netip.Addr]string)
	}
	if _, ok := m.ips[pool][addr]; ok {
		return fmt.Errorf("ip %s already allocated in pool %s", addr, pool)
	}
	m.ips[pool][addr] = owner

	return nil
}

func (m *mockIPAMAllocator) ReleaseIP(ip net.IP, pool ipam.Pool) error {
	addr := netipx.MustFromStdIP(ip)
	delete(m.ips[pool], addr)
	if len(m.ips[pool]) == 0 {
		delete(m.ips, pool)
	}

	return nil
}

type noopPostIPAMHandler struct{}

func (n *noopPostIPAMHandler) Handle(p ipamrestapi.PostIpamParams) middleware.Responder {
	return ipamrestapi.NewPostIpamCreated()
}

func newTestManager(t *testing.T) (*manager, *statedb.DB, statedb.RWTable[agentK8s.LocalPod], *mockEndpointMgr, *mockIPAMAllocator) {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
	}))

	mockLocalNode := node.LocalNode{
		Node: nodeTypes.Node{
			Name: "mock-node",
			IPAddresses: []nodeTypes.Address{
				{
					Type: addressing.NodeCiliumInternalIP,
					IP:   net.ParseIP("10.10.0.1"),
				},
				{
					Type: addressing.NodeCiliumInternalIP,
					IP:   net.ParseIP("fd00::1"),
				},
			},
			IPv4AllocCIDR: cidr.MustParseCIDR("10.10.0.0/24"),
			IPv6AllocCIDR: cidr.MustParseCIDR("fd00::0/96"),
		},
	}

	db := statedb.New()
	podTable, err := agentK8s.NewPodTable(db)
	require.NoError(t, err)

	mockEpMgr := newMockEndpointMgr()
	mockIPAMMetadata := newMockIPAMMetadata(db, podTable)
	mockIPAMAllocator := newMockIPAMAllocator()

	mgr := &manager{
		log: log,
		cfg: cfg{
			ipv4Enabled: true,
			ipv6Enabled: true,

			retryDuration: 1 * time.Millisecond,
			retryAttempts: 3,
		},
		endpointManager:     mockEpMgr,
		endpointTemplates:   ephemeralEndpointTemplates(),
		ipamMetadataManager: mockIPAMMetadata,
		ipam:                mockIPAMAllocator,
		localNodeStore:      node.NewTestLocalNodeStore(mockLocalNode),
		putEP:               mockEpMgr,
		ipamAlloc:           &noopPostIPAMHandler{},
		podTable:            podTable,
		db:                  db,
	}

	var endpointCreatorInterface endpointcreator.EndpointCreator = mockEpMgr
	mgr.endpointCreator.Store(&endpointCreatorInterface)

	return mgr, db, podTable, mockEpMgr, mockIPAMAllocator
}

type responseExtractor struct {
	headers http.Header
	body    strings.Builder
	code    int
}

func newResponseExtractor() *responseExtractor {
	return &responseExtractor{
		headers: make(http.Header),
	}
}

func (r *responseExtractor) Header() http.Header {
	return r.headers
}

func (r *responseExtractor) Write(bytes []byte) (int, error) {
	return r.body.Write(bytes)
}

func (r *responseExtractor) WriteHeader(statusCode int) {
	r.code = statusCode
}

type requireFunc func(*testing.T, *responseExtractor)

func withBody(body any) requireFunc {
	return func(t *testing.T, r *responseExtractor) {
		t.Helper()

		var sb strings.Builder
		producer := runtime.TextProducer()
		producer.Produce(&sb, body)

		require.Equal(t, sb.String(), r.body.String())
	}
}

func withStatusCode(code int) requireFunc {
	return func(t *testing.T, r *responseExtractor) {
		t.Helper()

		require.Equal(t, code, r.code, "got body: %v", r.body.String())
	}
}

func requireResponse(t *testing.T, got middleware.Responder, requires ...requireFunc) {
	t.Helper()
	extractor := newResponseExtractor()
	got.WriteResponse(extractor, runtime.TextProducer())
	for _, req := range requires {
		req(t, extractor)
	}
}

func Test_manager(t *testing.T) {
	m, db, podTable, epMgr, ipamAlloc := newTestManager(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	podA := &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "pod-a",
			Namespace: "cilium-test",
			UID:       "1234",
			Annotations: map[string]string{
				annotation.IPAMIPv4PoolKey: "ip-10-10-0-10",
				annotation.IPAMIPv6PoolKey: "fd00::10",
			},
		},
		Status: slim_corev1.PodStatus{
			Phase: slim_corev1.PodRunning,
		},
	}
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
		K8sNamespace:           podA.Namespace,
		K8sPodName:             podA.Name,
		K8sUID:                 string(podA.UID),
	}
	podB := &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "pod-b",
			Namespace: "cilium-test",
			UID:       "5678",
			Annotations: map[string]string{
				types.DetachedAnnotation:   `{"ipv4":"10.10.0.20","ipv6":"fd00::20"}`,
				annotation.IPAMIPv4PoolKey: "ip-10-10-0-20",
				annotation.IPAMIPv6PoolKey: "ip-fd00-20",
			},
		},
		Status: slim_corev1.PodStatus{
			Phase: slim_corev1.PodRunning,
		},
	}
	epB := &models.EndpointChangeRequest{
		Addressing: &models.AddressPair{
			IPV4:         "10.10.0.20",
			IPV4PoolName: "ip-10-10-0-20",
			IPV6:         "fd00::20",
			IPV6PoolName: "ip-fd00-20",
		},
		ContainerID:            "c5678",
		ContainerInterfaceName: "eth0",
		InterfaceName:          "veth_lxc_b",
		K8sNamespace:           podB.Namespace,
		K8sPodName:             podB.Name,
		K8sUID:                 string(podB.UID),
	}

	// IPAM request with missing pod in pod store should fail
	resp := m.handlePostIPAM(ipamrestapi.PostIpamParams{
		HTTPRequest: &http.Request{},
		Owner:       swag.String(podB.Namespace + "/" + podB.Name),
	})
	requireResponse(t, resp, withStatusCode(ipamrestapi.PostIpamFailureCode))
	require.Empty(t, ipamAlloc.ips)

	// Endpoint creation request with missing pod in pod store should fail
	resp = m.handlePutEndpointID(endpointrestapi.PutEndpointIDParams{
		HTTPRequest: &http.Request{},
		Endpoint:    epB,
	})
	requireResponse(t, resp, withStatusCode(endpointrestapi.PutEndpointIDFailedCode))
	require.Empty(t, epMgr.GetEndpointsByPodName(podA.Namespace+"/"+podA.Name))
	_, err := m.endpointTemplates.getEndpointTemplatesForPod(podA.UID)
	require.ErrorIs(t, err, fs.ErrNotExist)

	// Upsert pods, now endpoint creation requests should succeed
	txn := db.WriteTxn(podTable)
	podTable.Insert(txn, agentK8s.LocalPod{
		Pod: podA,
	})
	podTable.Insert(txn, agentK8s.LocalPod{
		Pod: podB,
	})
	txn.Commit()

	// Request for attached pod
	resp = m.handlePutEndpointID(endpointrestapi.PutEndpointIDParams{
		HTTPRequest: &http.Request{},
		Endpoint:    epA,
	})
	requireResponse(t, resp, withStatusCode(endpointrestapi.PutEndpointIDCreatedCode))
	require.Len(t, epMgr.GetEndpointsByPodName(podA.Namespace+"/"+podA.Name), 1)
	epTmpls, err := m.endpointTemplates.getEndpointTemplatesForPod(podA.UID)
	require.NoError(t, err)
	require.Len(t, epTmpls, 1)

	// IPAM request for detached pod, this tests if the DetachedAnnotation is parsed correctly
	resp = m.handlePostIPAM(ipamrestapi.PostIpamParams{
		HTTPRequest: &http.Request{},
		Owner:       swag.String(podB.Namespace + "/" + podB.Name),
	})
	requireResponse(t, resp,
		withStatusCode(ipamrestapi.PostIpamCreatedCode),
		withBody(&models.IPAMResponse{
			Address: &models.AddressPair{
				IPV4:         "10.10.0.20",
				IPV4PoolName: "ip-10-10-0-20",
				IPV6:         "fd00::20",
				IPV6PoolName: "ip-fd00-20",
			},
			HostAddressing: &models.NodeAddressing{
				IPV4: &models.NodeAddressingElement{
					Enabled:    true,
					IP:         "10.10.0.1",
					AllocRange: "10.10.0.0/24",
				},
				IPV6: &models.NodeAddressingElement{
					Enabled:    true,
					IP:         "fd00::1",
					AllocRange: "fd00::/96",
				},
			},
			IPV4: &models.IPAMAddressResponse{
				IP: "10.10.0.20",
			},
			IPV6: &models.IPAMAddressResponse{
				IP: "fd00::20",
			}}),
	)

	// Endpoint creation request for detached pod
	resp = m.handlePutEndpointID(endpointrestapi.PutEndpointIDParams{
		HTTPRequest: &http.Request{},
		Endpoint:    epB,
	})
	requireResponse(t, resp, withStatusCode(endpointrestapi.PutEndpointIDCreatedCode))
	require.Empty(t, epMgr.GetEndpointsByPodName(podB.Namespace+"/"+podB.Name))
	epTmpls, err = m.endpointTemplates.getEndpointTemplatesForPod(podB.UID)
	require.NoError(t, err)
	require.Len(t, epTmpls, 1)

	// Remove detached annotation from pod B, this should create an endpoint
	podB = podB.DeepCopy()
	delete(podB.Annotations, types.DetachedAnnotation)
	txn = db.WriteTxn(podTable)
	podTable.Insert(txn, agentK8s.LocalPod{
		Pod: podB,
	})
	txn.Commit()
	err = m.handlePodEvent(ctx, resource.Event[agentK8s.LocalPod]{
		Kind: resource.Upsert,
		Key: resource.Key{
			Name:      podB.Name,
			Namespace: podB.Namespace,
		},
		Object: agentK8s.LocalPod{
			Pod: podB,
		},
	})
	require.NoError(t, err)
	require.Len(t, epMgr.GetEndpointsByPodName(podB.Namespace+"/"+podB.Name), 1)
	require.Equal(t, podB.Namespace+"/"+podB.Name, ipamAlloc.ips["ip-10-10-0-20"][netip.MustParseAddr("10.10.0.20")])
	require.Equal(t, podB.Namespace+"/"+podB.Name, ipamAlloc.ips["ip-fd00-20"][netip.MustParseAddr("fd00::20")])

	// Add detached annotation to pod A, this should remove an endpoint
	podA = podA.DeepCopy()
	podA.Annotations[types.DetachedAnnotation] = `{"ipv4":"10.10.0.10","ipv6":"fd00::10"}`
	txn = db.WriteTxn(podTable)
	podTable.Insert(txn, agentK8s.LocalPod{
		Pod: podA,
	})
	txn.Commit()
	err = m.handlePodEvent(ctx, resource.Event[agentK8s.LocalPod]{
		Kind: resource.Upsert,
		Key: resource.Key{
			Name:      podA.Name,
			Namespace: podA.Namespace,
		},
		Object: agentK8s.LocalPod{
			Pod: podA,
		},
	})
	require.NoError(t, err)
	require.Empty(t, epMgr.GetEndpointsByPodName(podA.Namespace+"/"+podA.Name))

	// Removing pod should remove the endpoint template
	txn = db.WriteTxn(podTable)
	podTable.Delete(txn, agentK8s.LocalPod{Pod: podA})
	txn.Commit()
	err = m.handlePodEvent(ctx, resource.Event[agentK8s.LocalPod]{
		Kind: resource.Delete,
		Key: resource.Key{
			Name:      podA.Name,
			Namespace: podA.Namespace,
		},
		Object: agentK8s.LocalPod{
			Pod: podA,
		},
	})
	require.NoError(t, err)
	epTmpls, err = m.endpointTemplates.getEndpointTemplatesForPod(podA.UID)
	require.ErrorIs(t, err, fs.ErrNotExist)
	require.Empty(t, epTmpls)

	txn = db.WriteTxn(podTable)
	podTable.Delete(txn, agentK8s.LocalPod{Pod: podB})
	txn.Commit()
	err = m.handlePodEvent(ctx, resource.Event[agentK8s.LocalPod]{
		Kind: resource.Delete,
		Key: resource.Key{
			Name:      podB.Name,
			Namespace: podB.Namespace,
		},
		Object: agentK8s.LocalPod{
			Pod: podB,
		},
	})
	require.NoError(t, err)
	epTmpls, err = m.endpointTemplates.getEndpointTemplatesForPod(podB.UID)
	require.ErrorIs(t, err, fs.ErrNotExist)
	require.Empty(t, epTmpls)

}

func Test_manager_handlePodEvent_sync(t *testing.T) {
	m, db, podTable, _, _ := newTestManager(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Simulate endpoint templates from before agent restart
	for i := range 15 {
		err := m.endpointTemplates.persistEndpointTemplate(&models.EndpointChangeRequest{
			K8sPodName:   fmt.Sprintf("pod-%d", i),
			K8sNamespace: "cilium-test",
			K8sUID:       strconv.Itoa(i),
		})
		require.NoError(t, err)
	}

	// Insert live pods (pod-0 to pod-9) into pod store
	txn := db.WriteTxn(podTable)
	for i := range 10 {
		podTable.Insert(txn, agentK8s.LocalPod{
			Pod: &slim_corev1.Pod{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:      fmt.Sprintf("pod-%d", i),
					Namespace: "cilium-test",
					UID:       k8sTypes.UID(strconv.Itoa(i)),
				},
				Status: slim_corev1.PodStatus{
					Phase: slim_corev1.PodRunning,
				},
			},
		})
	}
	txn.Commit()

	err := m.handlePodEvent(ctx, resource.Event[agentK8s.LocalPod]{
		Kind: resource.Sync,
	})
	require.NoError(t, err)

	// Check live pods still have templates
	for i := range 10 {
		uid := k8sTypes.UID(strconv.Itoa(i))
		epTmpl, err := m.endpointTemplates.getEndpointTemplatesForPod(uid)
		require.NoError(t, err)
		require.Len(t, epTmpl, 1)
		require.Equal(t, string(uid), epTmpl[0].K8sUID)
	}

	// Check removed pods have been pruned
	for i := 10; i < 15; i++ {
		uid := k8sTypes.UID(strconv.Itoa(i))
		epTmpl, err := m.endpointTemplates.getEndpointTemplatesForPod(uid)
		require.ErrorIs(t, err, fs.ErrNotExist)
		require.Empty(t, epTmpl)
	}
}
