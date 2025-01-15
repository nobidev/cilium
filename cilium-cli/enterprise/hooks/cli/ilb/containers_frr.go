//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
)

type frrContainer struct {
	dockerContainer
}

type frrShowBGPOut struct {
	Routes map[string][]struct{} `json:"routes"`
}

func (c *frrContainer) vty(ctx context.Context, cmd string) (string, string, error) {
	return c.Exec(ctx, fmt.Sprintf(`vtysh -c "%s"`, cmd))
}

func (c *frrContainer) bgpRoutes(ctx context.Context, afi, safi string) (sets.Set[netip.Prefix], error) {
	stdout, stderr, err := c.vty(ctx, "show bgp "+afi+" "+safi+" json")
	if err != nil {
		return nil, fmt.Errorf("failed to show bgp routes: stdout: %s stderr: %s err: %w", stdout, stderr, err)
	}

	out := frrShowBGPOut{}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		return nil, fmt.Errorf("failed to unmarshal show bgp output: %w", err)
	}

	prefixes := sets.New[netip.Prefix]()
	for prefix := range out.Routes {
		prefixes.Insert(netip.MustParsePrefix(prefix))
	}

	return prefixes, nil
}

type ipRouteShowOut []struct {
	Dst string `json:"dst"`
}

func (c *frrContainer) ipRoutes(ctx context.Context) (sets.Set[netip.Prefix], error) {
	stdout, stderr, err := c.Exec(ctx, "ip -4 -j route show")
	if err != nil {
		return nil, fmt.Errorf("failed to show ip routes: stdout: %s stderr: %s err: %w", stdout, stderr, err)
	}

	out := ipRouteShowOut{}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ip route show output: %w", err)
	}

	prefixes := sets.New[netip.Prefix]()
	for _, r := range out {
		if r.Dst == "default" {
			r.Dst = "0.0.0.0/0"
		} else if !strings.Contains(r.Dst, "/") {
			r.Dst += "/32"
		}
		p, err := netip.ParsePrefix(r.Dst)
		if err != nil {
			return nil, fmt.Errorf("failed to parse prefix %q: %w", r.Dst, err)
		}
		prefixes.Insert(p)
	}

	return prefixes, nil
}

// EnsureRoute ensures that the given BGP prefix is present in the BGP
// routes and installed in the FRR container.
func (c *frrContainer) EnsureRoute(ctx context.Context, prefix string) error {
	p := netip.MustParsePrefix(prefix)
	if !p.Addr().Is4() {
		fatalf("only IPv4 prefix is supported")
	}

	ribPrefixes, err := c.bgpRoutes(ctx, "ipv4", "unicast")
	if err != nil {
		return err
	}

	if !ribPrefixes.Has(p) {
		return fmt.Errorf("prefix %s not found in BGP routes", p)
	}

	fibPrefixes, err := c.ipRoutes(ctx)
	if err != nil {
		return err
	}

	if !fibPrefixes.Has(p) {
		return fmt.Errorf("prefix %s not found in FIB routes", p)
	}

	return nil
}
