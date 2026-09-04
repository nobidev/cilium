// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"

	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/time"
)

type dnsInjector interface {
	RecordAndGenerate(ctx context.Context, lookupTime time.Time, ep *endpoint.Endpoint, qname string, responseIPs []netip.Addr, TTL int) bool
}

// fqdnLookupCmd returns a command that injects a DNS answer for an endpoint,
// as if it had resolved the name through the DNS proxy.
func fqdnLookupCmd(epl endpointmanager.EndpointsLookup, injector dnsInjector) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Inject a DNS answer for an endpoint",
			Args:    "ep-id name ip[,ip...]",
			Flags: func(fs *pflag.FlagSet) {
				fs.Int("ttl", 60, "TTL of the DNS answer in seconds")
			},
			Detail: []string{
				"Records a DNS name to IP mapping in the source endpoint's DNS",
				"history and pushes it through the name manager, the way the DNS",
				"proxy does after an endpoint resolves a name. The endpoint is a",
				"numeric ID or a namespace/podname.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 3 {
				return nil, fmt.Errorf("expected three args (ep-id name ip) but got %d", len(args))
			}
			epSpec, name, ipList := args[0], args[1], args[2]

			// Canonicalize the name the way the DNS proxy does before it
			// reaches the name manager, so a toFQDNs selector matches it.
			name = dns.FQDN(name)

			ttl, err := s.Flags.GetInt("ttl")
			if err != nil {
				return nil, err
			}

			ep, err := lookupEP(epl, epSpec)
			if err != nil {
				return nil, err
			}

			var ips []netip.Addr
			for raw := range strings.SplitSeq(ipList, ",") {
				ip, err := netip.ParseAddr(strings.TrimSpace(raw))
				if err != nil {
					return nil, fmt.Errorf("invalid ip %q: %w", raw, err)
				}
				ips = append(ips, ip)
			}

			return func(*script.State) (stdout, stderr string, err error) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if !injector.RecordAndGenerate(ctx, time.Now(), ep, name, ips, ttl) {
					return "", "", fmt.Errorf("timed out generating policy for %s", name)
				}
				return fmt.Sprintf("%s -> %v (ttl %d) for endpoint %d\n", name, ips, ttl, ep.ID), "", nil
			}, nil
		},
	)
}

func lookupEP(epl endpointmanager.EndpointsLookup, spec string) (*endpoint.Endpoint, error) {
	if id, err := strconv.Atoi(spec); err == nil {
		if id <= 0 || id > math.MaxUint16 {
			return nil, fmt.Errorf("invalid endpoint id %s", spec)
		}
		ep := epl.LookupCiliumID(uint16(id))
		if ep == nil {
			return nil, fmt.Errorf("no endpoint with ID %d", id)
		}
		return ep, nil
	}
	eps := epl.GetEndpointsByPodName(spec)
	if len(eps) != 1 {
		return nil, fmt.Errorf("expected one endpoint for %s but got %d", spec, len(eps))
	}
	return eps[0], nil
}
