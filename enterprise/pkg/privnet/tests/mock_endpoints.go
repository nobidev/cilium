//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"os"
	"slices"
	"testing"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/promise"
)

func mockEndpointCell(t testing.TB) cell.Cell {
	t.Helper()

	return cell.Group(
		cell.ProvidePrivate(
			newFakeRestorer,
			newFakeEPM,
		),
		cell.Provide(
			regeneration.NewFence,

			func(f *fakeEPM) uhive.ScriptCmdsOut { return uhive.NewScriptCmds(f.cmds()) },
			func(f *fakeRestorer) promise.Promise[endpointstate.Restorer] { return f },
		),
		cell.DecorateAll(func(f *fakeEPM) endpoints.EndpointGetter { return f }),
		cell.DecorateAll(func(f *fakeEPM) endpoints.EndpointCreator { return f }),
		cell.DecorateAll(func(f *fakeEPM) endpoints.EndpointRemover { return f }),
	)
}

type fakeEP struct {
	mu lock.Mutex

	ID uint16

	IPv4 netip.Addr
	IPv6 netip.Addr
	MAC  mac.MAC

	PodName   string
	Namespace string

	Properties map[string]any
}

var _ endpoints.Endpoint = &fakeEP{}

// GetID16 implements endpoints.Endpoint.
func (f *fakeEP) GetID16() uint16 {
	return f.ID
}

// IPv4Address implements endpoints.Endpoint.
func (f *fakeEP) IPv4Address() netip.Addr {
	return f.IPv4
}

// GetIPv4Address implements endpoints.Endpoint.
func (f *fakeEP) GetIPv4Address() string {
	if f.IPv4.IsValid() {
		return f.IPv4.String()
	}
	return ""
}

// IPv6Address implements endpoints.Endpoint.
func (f *fakeEP) IPv6Address() netip.Addr {
	return f.IPv6
}

// GetIPv6Address implements endpoints.Endpoint.
func (f *fakeEP) GetIPv6Address() string {
	if f.IPv6.IsValid() {
		return f.IPv6.String()
	}
	return ""
}

// GetK8sCEPName implements endpoints.Endpoint.
func (f *fakeEP) GetK8sCEPName() string {
	if cepName, ok := f.Properties[endpoint.PropertyCEPName]; ok {
		return cepName.(string)
	}
	return f.PodName
}

// GetK8sNamespaceAndCEPName implements endpoints.Endpoint.
func (f *fakeEP) GetK8sNamespaceAndCEPName() string {
	return fmt.Sprintf("%s/%s", f.Namespace, f.GetK8sCEPName())
}

// GetK8sNamespaceAndPodName implements endpoints.Endpoint.
func (f *fakeEP) GetK8sNamespaceAndPodName() string {
	return fmt.Sprintf("%s/%s", f.Namespace, f.PodName)
}

// GetPropertyValue implements endpoints.Endpoint.
func (f *fakeEP) GetPropertyValue(key string) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Properties == nil {
		return nil
	}
	return f.Properties[key]
}

// SetPropertyValue implements endpoints.Endpoint.
func (f *fakeEP) SetPropertyValue(key string, value any) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Properties == nil {
		f.Properties = map[string]any{}
	}
	f.Properties[key] = value
	return value
}

// LXCMac implements endpoints.Endpoint.
func (f *fakeEP) LXCMac() mac.MAC {
	return f.MAC
}

// SyncEndpointHeaderFile implements endpoints.Endpoint.
func (f *fakeEP) SyncEndpointHeaderFile() {}

// fakeEPM implements endpoints.Endpoint{Creator,Getter,Remover}
type fakeEPM struct {
	mu   lock.Mutex
	eps  []*fakeEP
	subs []endpoints.EndpointSubscriber

	restorer *fakeRestorer
}

func newFakeEPM(restorer *fakeRestorer, fence regeneration.Fence, jg job.Group) *fakeEPM {
	// wait for regeneration fence to unblock
	jg.Add(job.OneShot("wait-for-restore", func(ctx context.Context, health cell.Health) error {
		err := fence.Wait(ctx)
		if err != nil {
			return err
		}
		restorer.finishRestoration()
		return nil
	}))

	return &fakeEPM{
		subs: []endpoints.EndpointSubscriber{},
		eps:  []*fakeEP{},

		restorer: restorer,
	}
}

// fakeRestorer implements endpointstate.Restorer, and
// promise.Promise[endpointstate.Restorer] (resolving to itself)
type fakeRestorer struct {
	ch chan struct{}
}

func newFakeRestorer() *fakeRestorer {
	return &fakeRestorer{
		ch: make(chan struct{}),
	}
}

func (f *fakeRestorer) waitForRestore(ctx context.Context) error {
	select {
	case <-f.ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *fakeRestorer) finishRestoration() {
	close(f.ch)
}

func (f *fakeRestorer) isRestored() bool {
	select {
	case <-f.ch:
		return true
	default:
		return false
	}
}

// WaitForEndpointRestore implements endpointstate.Restorer.
func (f *fakeRestorer) WaitForEndpointRestore(ctx context.Context) error {
	return f.waitForRestore(ctx)
}

// WaitForInitialPolicy implements endpointstate.Restorer.
func (f *fakeRestorer) WaitForInitialPolicy(ctx context.Context) error {
	return f.waitForRestore(ctx)
}

// Await implements promise.Promise.
func (f *fakeRestorer) Await(context.Context) (endpointstate.Restorer, error) {
	return f, nil
}

// CreateEndpoint implements endpoints.EndpointCreator.
func (f *fakeEPM) createEndpoint(epTemplate *models.EndpointChangeRequest, restored bool) (endpoints.Endpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var err error
	ep := fakeEP{
		ID:         uint16(epTemplate.ID),
		PodName:    epTemplate.K8sPodName,
		Namespace:  epTemplate.K8sNamespace,
		Properties: epTemplate.Properties,
	}
	if epTemplate.Addressing.IPV4 != "" {
		ep.IPv4, err = netip.ParseAddr(epTemplate.Addressing.IPV4)
		if err != nil {
			return nil, err
		}
	}
	if epTemplate.Addressing.IPV6 != "" {
		ep.IPv6, err = netip.ParseAddr(epTemplate.Addressing.IPV6)
		if err != nil {
			return nil, err
		}
	}
	if epTemplate.Mac != "" {
		ep.MAC, err = mac.ParseMAC(epTemplate.Mac)
		if err != nil {
			return nil, err
		}
	}

	f.eps = append(f.eps, &ep)
	for _, sub := range f.subs {
		if restored {
			sub.EndpointRestored(&ep)
		} else {
			sub.EndpointCreated(&ep)
		}
	}
	return &ep, nil
}

// CreateEndpoint implements endpoints.EndpointCreator.
func (f *fakeEPM) CreateEndpoint(ctx context.Context, epTemplate *models.EndpointChangeRequest) (endpoints.Endpoint, error) {
	ep, err := f.createEndpoint(epTemplate, false)
	return ep, err
}

// RemoveByCEPName implements endpoints.EndpointRemover.
func (f *fakeEPM) RemoveByCEPName(nsname string) (endpoints.Endpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := slices.IndexFunc(f.eps, func(ep *fakeEP) bool {
		return ep.GetK8sNamespaceAndCEPName() == nsname
	})
	if i < 0 {
		return nil, fmt.Errorf("no endpoint found for CEP %q", nsname)
	}
	ep := f.eps[i]
	f.eps = slices.Delete(f.eps, i, i+1)
	for _, sub := range f.subs {
		sub.EndpointDeleted(ep)
	}
	return ep, nil
}

// GetEndpointsByPodName implements endpoints.EndpointGetter.
func (f *fakeEPM) GetEndpointsByPodName(nsname string) iter.Seq[endpoints.Endpoint] {
	return func(yield func(endpoints.Endpoint) bool) {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, ep := range f.eps {
			if ep.GetK8sNamespaceAndPodName() == nsname {
				if !yield(ep) {
					return
				}
			}
		}
	}
}

// LookupCEPName implements endpoints.EndpointGetter.
func (f *fakeEPM) LookupCEPName(nsname string) (ep endpoints.Endpoint) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.eps {
		if f.eps[i].GetK8sNamespaceAndCEPName() == nsname {
			return f.eps[i]
		}
	}
	return nil
}

// Subscribe implements endpoints.EndpointGetter.
func (f *fakeEPM) Subscribe(s endpoints.EndpointSubscriber) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subs = append(f.subs, s)
}

func (f *fakeEPM) cmds() map[string]script.Cmd {
	return map[string]script.Cmd{
		"privnet/epm-create":  f.createEPCmd(),
		"privnet/epm-delete":  f.deleteEPCmd(),
		"privnet/epm-restore": f.restoreEPCmd(),
	}
}

func parseEndpointJSON(s *script.State, args []string) (*models.EndpointChangeRequest, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("%w: expected number of arguments", script.ErrUsage)
	}
	b, err := os.ReadFile(s.Path(args[0]))
	if err != nil {
		return nil, err
	}
	epr := &models.EndpointChangeRequest{}
	err = json.Unmarshal(b, epr)
	if err != nil {
		return nil, err
	}
	return epr, nil
}

func (f *fakeEPM) createEPCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "create a fake endpoint",
			Args:    "ep-req-json-file",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			epr, err := parseEndpointJSON(s, args)
			if err != nil {
				return nil, err
			}
			_, err = f.createEndpoint(epr, false)
			if err != nil {
				return nil, fmt.Errorf("fake endpoint creation failed: %w", err)
			}

			return nil, nil
		},
	)
}

func (f *fakeEPM) restoreEPCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "restore a fake endpoint",
			Args:    "ep-req-json-file",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if f.restorer.isRestored() {
				return nil, errors.New("cannot restore endpoints after regeneration has already started")
			}
			epr, err := parseEndpointJSON(s, args)
			if err != nil {
				return nil, err
			}
			_, err = f.createEndpoint(epr, true)
			if err != nil {
				return nil, fmt.Errorf("fake endpoint creation failed: %w", err)
			}

			return nil, nil
		},
	)
}

func (f *fakeEPM) deleteEPCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "delete a fake endpoint",
			Args:    "cep-name",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("%w: expected number of arguments", script.ErrUsage)
			}
			_, err := f.RemoveByCEPName(args[0])
			if err != nil {
				return nil, fmt.Errorf("fake endpoint deletion failed: %w", err)
			}

			return nil, nil
		},
	)
}
