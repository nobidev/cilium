// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package forklift

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	whcfg "github.com/cilium/cilium/enterprise/operator/pkg/privnet/webhook/config"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/safeio"
)

type Inventory interface {
	// NetworkInfoFor retrieves from the inventory and returns the network
	// information for the given virtual machine.
	NetworkInfoForVM(context.Context, labeled) (NetworkInfo, error)
}

// NetworkInfo wraps the network information associated with a given VM.
type NetworkInfo struct {
	// Interfaces is the list of interfaces retrieved from the Forklift inventory.
	Interfaces []Interface

	// PreserveStaticIPs is true if the plan associated with the given VM has
	// the PreserveStaticIPs flag set.
	PreserveStaticIPs bool
}

// ByMAC returns the interface associated with the given MAC address, or false otherwise.
func (ni *NetworkInfo) ByMAC(mac mac.MAC) (Interface, bool) {
	for _, iface := range ni.Interfaces {
		if bytes.Equal(mac, iface.MAC) {
			return iface, true
		}
	}

	return Interface{}, false
}

// Interface contains the main information associated with a given VM interface.
type Interface struct {
	MAC  mac.MAC
	IPv4 netip.Addr
	IPv6 netip.Addr
}

type inventory struct {
	log *slog.Logger

	cfg    Config
	client *http.Client
	vault  TokenVault

	db        *statedb.DB
	plans     statedb.Table[Plan]
	providers statedb.Table[Provider]
}

func newInventory(in struct {
	cell.In

	Lifecycle cell.Lifecycle
	JobGroup  job.Group
	Log       *slog.Logger

	WebhookCfg whcfg.Config
	Config     Config

	ServiceResolver dial.Resolver `optional:"true"`

	DB        *statedb.DB
	Plans     statedb.Table[Plan]
	Providers statedb.Table[Provider]
}) (Inventory, error) {
	var inventory = inventory{
		log: in.Log,

		cfg: in.Config,

		db:        in.DB,
		plans:     in.Plans,
		providers: in.Providers,
	}

	switch {
	case !in.WebhookCfg.Enabled:
		return &inventory, nil
	case in.Config.URL == "":
		return nil, errors.New("Private networks webhook is enabled, but Forklift URL is unset")
	case in.Config.BearerTokenPath == "":
		return nil, errors.New("Private networks webhook is enabled, but the Forklift bearer token is not provided")
	}

	inventory.vault = newTokenVault(in.Config.BearerTokenPath, in.Lifecycle, in.JobGroup)
	bundle, err := inventory.loadCABundle()
	if err != nil {
		return nil, err
	}

	var dialer func(ctx context.Context, _, addr string) (net.Conn, error)
	if in.ServiceResolver != nil {
		dialer = func(ctx context.Context, _, addr string) (net.Conn, error) {
			// Bypass CoreDNS for service IP resolution,
			return dial.NewContextDialer(in.Log, in.ServiceResolver)(ctx, addr)
		}
	}

	inventory.client = &http.Client{
		Transport: &http.Transport{
			DialContext: dialer,
			TLSClientConfig: &tls.Config{
				RootCAs: bundle,

				// Same settings as the various Cilium API servers.
				PreferServerCipherSuites: true,
				CurvePreferences:         []tls.CurveID{tls.CurveP256},
				NextProtos:               []string{"http/1.1"},
				MinVersion:               tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				},
			},
		},
	}

	return &inventory, nil
}

func (i *inventory) NetworkInfoForVM(ctx context.Context, obj labeled) (NetworkInfo, error) {
	if !IsMigratedVM(obj) {
		return NetworkInfo{}, errors.New("not a migrated VM")
	}

	plan, err := get(ctx, i.db, i.plans, PlanByUID(GetPlanID(obj)))
	if err != nil {
		return NetworkInfo{}, fmt.Errorf("retrieving plan %s: %w", GetPlanID(obj), err)
	}

	provider, err := get(ctx, i.db, i.providers, ProviderByUID(plan.SourceProvider.UID))
	if err != nil {
		return NetworkInfo{}, fmt.Errorf("retrieving source provider %s: %w", plan.SourceProvider.UID, err)
	}

	switch provider.Type {
	case ProviderTypeVsphere:
		return i.fromVsphere(ctx, GetVMID(obj), provider, plan)
	default:
		return NetworkInfo{}, fmt.Errorf("unsupported source provider type %q", provider.Type)
	}
}

func (i *inventory) fromVsphere(ctx context.Context, vmID string, provider Provider, plan Plan) (NetworkInfo, error) {
	var vm vmInfo
	err := i.doRequest(ctx, &vm, provider, "vms", vmID)
	if err != nil {
		return NetworkInfo{}, fmt.Errorf("looking up VM: %w", err)
	}

	ifaces, err := vm.toInterfaces()
	if err != nil {
		return NetworkInfo{}, fmt.Errorf("parsing VM: %w", err)
	}

	return NetworkInfo{
		Interfaces:        ifaces,
		PreserveStaticIPs: plan.PreserveStaticIPs,
	}, nil
}

func (i *inventory) doRequest(ctx context.Context, into any, provider Provider, els ...string) error {
	uri, err := url.JoinPath(i.cfg.URL, append([]string{"providers", string(provider.Type), string(provider.UID)}, els...)...)
	if err != nil {
		return fmt.Errorf("constructing request URI: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", uri, http.NoBody)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Add("Authorization", "Bearer "+i.vault.Token())

	resp, err := i.client.Do(req)
	if err != nil {
		return fmt.Errorf("performing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %s", resp.Status)
	}

	body, err := safeio.ReadAllLimit(resp.Body, safeio.MB)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	err = json.Unmarshal(body, into)
	if err != nil {
		return fmt.Errorf("unmarshaling response: %w", err)
	}

	return nil
}

func (i *inventory) loadCABundle() (*x509.CertPool, error) {
	if i.cfg.CAPath == "" {
		// Fallback to using the host's root CA set.
		return nil, nil
	}

	certs, err := os.ReadFile(i.cfg.CAPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA bundle from %s: %w", i.cfg.CAPath, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certs) {
		return nil, fmt.Errorf("reading CA bundle from %s: no valid certificate found", i.cfg.CAPath)
	}

	return pool, nil
}

// get retries a Get query until either an object is found, or the context is canceled.
// We leverage it to avoid failing hard in case we haven't observed yet the target
// object, which may happen in case it is created more or less at the same time of
// the webhook request.
func get[T any](ctx context.Context, db *statedb.DB, tbl statedb.Table[T], query statedb.Query[T]) (T, error) {
	for {
		obj, _, watch, found := tbl.GetWatch(db.ReadTxn(), query)
		if found {
			return obj, nil
		}

		select {
		case <-watch:
		case <-ctx.Done():
			return obj, errors.New("not found")
		}
	}
}

type vmInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`

	GuestNetworks []vmGuestNetwork `json:"guestNetworks"`
}

type vmGuestNetwork struct {
	Device string     `json:"device"`
	MAC    mac.MAC    `json:"mac"`
	IP     netip.Addr `json:"ip"`
}

func (vm *vmInfo) toInterfaces() ([]Interface, error) {
	var ifaces = make(map[string]Interface)
	for _, net := range vm.GuestNetworks {
		iface := ifaces[net.Device]

		if len(iface.MAC) != 0 && !bytes.Equal(iface.MAC, net.MAC) {
			return nil, fmt.Errorf("mismatching MAC address for device %q", net.Device)
		}
		iface.MAC = net.MAC

		switch {
		case net.IP.IsLoopback() || net.IP.IsLinkLocalUnicast() || net.IP.IsMulticast():
			ifaces[net.Device] = iface
			continue

		case net.IP.Is4() && iface.IPv4 == netip.Addr{}:
			iface.IPv4 = net.IP
		case net.IP.Is4():
			return nil, fmt.Errorf("multiple global IPv4 addresses for device %q", net.Device)

		case net.IP.Is6() && iface.IPv6 == netip.Addr{}:
			iface.IPv6 = net.IP
		case net.IP.Is6():
			return nil, fmt.Errorf("multiple global IPv6 addresses for device %q", net.Device)
		}

		ifaces[net.Device] = iface
	}

	for dev, iface := range ifaces {
		if len(iface.MAC) == 0 {
			return nil, fmt.Errorf("unknown MAC address for device %q", dev)
		}
	}

	return slices.Collect(maps.Values(ifaces)), nil
}
