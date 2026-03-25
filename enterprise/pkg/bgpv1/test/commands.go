// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/hive"
	"github.com/cilium/hive/script"
	gobgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"

	ceeCommands "github.com/cilium/cilium/enterprise/pkg/bgpv1/commands"
	"github.com/cilium/cilium/pkg/bgp/api"
	"github.com/cilium/cilium/pkg/bgp/gobgp"
	"github.com/cilium/cilium/pkg/bgp/test/commands"
	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	client "github.com/cilium/cilium/pkg/k8s/client/testutils"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
)

const (
	communitiesFlag      = "communities"
	communitiesFlagShort = "c"
)

// BGPTestScriptCmds are special purpose script commands for BGP Control Plane tests.
func BGPTestScriptCmds(clientSet *client.FakeClientset, writer *writer.Writer, egwMgr *egwManagerMock) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"bgptest/sync-oss-resources": SyncOSSResourcesCommand(clientSet),
		"bgptest/upsert-egw-policy":  UpsertEGWPolicyCommand(egwMgr),
		"bgptest/set-backend-health": SetBackendHealthCommand(writer),
	})
}

// UpsertEGWPolicyCommand upserts mocked Egress Gateway Policy data for the test.
func UpsertEGWPolicyCommand(egwMgr *egwManagerMock) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Upsert Egress Gateway Policy data in the test",
			Args:    "name labels egress-ips",
			Detail: []string{
				"Update/insert mock Egress Gateway Policy data in the test.",
				"",
				"'name' is the name of the EGW policy.",
				"'labels' is a set of key=value labels of the policy separated by colon, e.g. 'key1=value1,key2=value2'.",
				"'egress-ips' is list of IP addresses used as egress IPs by the policy.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 3 {
				return nil, fmt.Errorf("invalid command format, should be: 'bgptest/upsert-egw-policy name labels egress-ips'")
			}
			labels := make(map[string]string)
			for label := range strings.SplitSeq(args[1], ",") {
				parts := strings.Split(label, "=")
				if len(parts) != 2 {
					return nil, fmt.Errorf("invalid label format: '%s'", label)
				}
				labels[parts[0]] = parts[1]
			}
			egressIPs := make([]netip.Addr, 0)
			for ip := range strings.SplitSeq(args[2], ",") {
				if ip == "" {
					continue
				}
				ipAddr, err := netip.ParseAddr(ip)
				if err != nil {
					return nil, fmt.Errorf("invalid egw IP address: %s", ip)
				}
				egressIPs = append(egressIPs, ipAddr)
			}
			policy := mockEGWPolicy{
				id:        k8stypes.NamespacedName{Name: args[0]},
				labels:    labels,
				egressIPs: egressIPs,
			}
			s.Logf("Upserting EGW Policy: %s (labels: %v, IPs: %v)", policy.id.Name, policy.labels, policy.egressIPs)
			egwMgr.updateMockPolicy(policy)
			return nil, nil
		},
	)
}

func SetBackendHealthCommand(writer *writer.Writer) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Set the number of healthy backends for given frontend",
			Args:    "frontend-addr backend-count",
			Detail: []string{
				"Look up the frontend and iterate over its backends setting the first",
				"<backend-count> as healthy and rest as unhealthy.",
				"",
				"'frontend-addr' is the  frontend address of the service in the L3n4Addr format, e.g. '172.16.1.1:80/TCP'.",
				"'backend-count' is the number of healthy backends that should be reported by the mock service health check manager.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			var addr lb.L3n4Addr
			err := addr.ParseFromString(args[0])
			if err != nil {
				return nil, fmt.Errorf("invalid frontend address: %s", args[0])
			}
			backendCount, err := strconv.Atoi(args[1])
			if err != nil {
				return nil, fmt.Errorf("invalid backend count: %s", args[1])
			}

			txn := writer.WriteTxn()

			fe, _, found := writer.Frontends().Get(txn, lb.FrontendByAddress(addr))
			if !found {
				return nil, fmt.Errorf("frontend %s not found", addr.StringWithProtocol())
			}

			for be := range fe.Backends {
				writer.UpdateBackendHealth(txn, fe.ServiceName, be.Address, backendCount > 0)
				backendCount--
			}

			txn.Commit()
			return nil, nil
		},
	)
}

// SyncOSSResourcesCommand syncs existing CEE BGP CRD resources to the respective OSS BGP CRD resources.
// For each IsovalentBGP* resource, respective CiliumBGP* resource with the same name is created.
func SyncOSSResourcesCommand(clientSet *client.FakeClientset) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Syncs enterprise BGP CRD resources to the respective OSS BGP CRD resources",
			Detail: []string{
				"For each IsovalentBGPNodeConfigs, IsovalentBGPNodeConfigs, IsovalentBGPPeerConfigs and IsovalentBGPAdvertisements",
				"resource, respective CiliumBGP* resource with the same name is created/updated/deleted to maintain 1:1 mapping.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			var err error
			// NOTE: unfortunately, could not make the dynamic client-go client work with the FakeClientset,
			// so we need to work with the typed clients here, which results in a bit of code duplication.

			// IsovalentBGPNodeConfigs -> CiliumBGPNodeConfigs
			ossMap := make(map[string]struct{})
			ceeMap := make(map[string]any)
			ossNodeConfigs, err := clientSet.CiliumV2().CiliumBGPNodeConfigs().List(s.Context(), metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			for _, nc := range ossNodeConfigs.Items {
				ossMap[nc.Name] = struct{}{}
			}
			ceeNodeConfigs, err := clientSet.IsovalentV1().IsovalentBGPNodeConfigs().List(s.Context(), metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			for _, nc := range ceeNodeConfigs.Items {
				ceeMap[nc.Name] = nc
			}
			err = syncResources[v2.CiliumBGPNodeConfig](s.Context(), ceeMap, ossMap, clientSet.CiliumV2().CiliumBGPNodeConfigs())
			if err != nil {
				return nil, err
			}

			// IsovalentPeerConfigs -> CiliumBGPPeerConfigs
			ossMap = make(map[string]struct{})
			ceeMap = make(map[string]any)
			ossPeerConfigs, err := clientSet.CiliumV2().CiliumBGPPeerConfigs().List(s.Context(), metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			for _, nc := range ossPeerConfigs.Items {
				ossMap[nc.Name] = struct{}{}
			}
			ceePeerConfigs, err := clientSet.IsovalentV1().IsovalentBGPPeerConfigs().List(s.Context(), metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			for _, pc := range ceePeerConfigs.Items {
				ceeMap[pc.Name] = pc
			}
			err = syncResources[v2.CiliumBGPPeerConfig](s.Context(), ceeMap, ossMap, clientSet.CiliumV2().CiliumBGPPeerConfigs())
			if err != nil {
				return nil, err
			}

			// IsovalentBGPAdvertisements -> CiliumBGPAdvertisements
			ossMap = make(map[string]struct{})
			ceeMap = make(map[string]any)
			ossAdverts, err := clientSet.CiliumV2().CiliumBGPAdvertisements().List(s.Context(), metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			for _, nc := range ossAdverts.Items {
				ossMap[nc.Name] = struct{}{}
			}
			ceeAdverts, err := clientSet.IsovalentV1().IsovalentBGPAdvertisements().List(s.Context(), metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			for _, a := range ceeAdverts.Items {
				ceeMap[a.Name] = a
			}
			err = syncResources[v2.CiliumBGPAdvertisement](s.Context(), ceeMap, ossMap, clientSet.CiliumV2().CiliumBGPAdvertisements())
			if err != nil {
				return nil, err
			}

			return nil, nil
		},
	)
}

// resourceClient is a common interface of typed k8s resource clients.
type resourceClient[T any] interface {
	Create(ctx context.Context, r *T, opts metav1.CreateOptions) (*T, error)
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*T, error)
	Update(ctx context.Context, r *T, opts metav1.UpdateOptions) (*T, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
}

// syncResources syncs resources from the srcResources map with resources in the dstResources map
// and applies the delta using the provided dstClient. Content os the srcResources is mapped 1:1 to the destination resources,
// with non-existent fields silently dropped.
func syncResources[T any](ctx context.Context, srcResources map[string]any, dstResources map[string]struct{}, dstClient resourceClient[T]) error {
	for name, src := range srcResources {
		var dst T
		err := copyResourceContent(&src, &dst)
		if err != nil {
			return err
		}
		if _, exists := dstResources[name]; !exists {
			_, err = dstClient.Create(ctx, &dst, metav1.CreateOptions{FieldValidation: "Ignore"})
		} else {
			current, err := dstClient.Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			rv, err := getResourceVersion(current)
			if err != nil {
				return err
			}
			err = setResourceVersion(&dst, rv)
			if err != nil {
				return err
			}
			_, err = dstClient.Update(ctx, &dst, metav1.UpdateOptions{FieldValidation: "Ignore"})
			return err
		}
		if err != nil {
			return err
		}
		delete(dstResources, name)
	}
	for name := range dstResources {
		err := dstClient.Delete(ctx, name, metav1.DeleteOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}

func copyResourceContent(src, dst any) error {
	srcUnstructured, err := convertToUnstructured(src)
	if err != nil {
		return err
	}
	dstUnstructured, err := convertToUnstructured(dst)
	if err != nil {
		return err
	}
	dstUnstructured.SetUnstructuredContent(srcUnstructured.UnstructuredContent())
	return convertFromUnstructured(dstUnstructured, dst)
}

func getResourceVersion(obj any) (string, error) {
	unstructuredObj, err := convertToUnstructured(obj)
	if err != nil {
		return "", err
	}
	return unstructuredObj.GetResourceVersion(), nil
}

func setResourceVersion(obj any, rv string) error {
	unstructuredObj, err := convertToUnstructured(obj)
	if err != nil {
		return err
	}
	unstructuredObj.SetResourceVersion(rv)
	return convertFromUnstructured(unstructuredObj, obj)
}

func convertToUnstructured(obj any) (*unstructured.Unstructured, error) {
	unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, err
	}
	return &unstructured.Unstructured{Object: unstructuredMap}, nil
}

func convertFromUnstructured(unstructuredObj *unstructured.Unstructured, obj any) error {
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.Object, obj)
	if err != nil {
		return err
	}
	return nil
}

// CEEGoBGPScriptCmds are cee-specific GoBGP commands
func CEEGoBGPScriptCmds(cmdCtx *commands.GoBGPCmdContext) map[string]script.Cmd {
	return map[string]script.Cmd{
		"gobgp/add-route":    AddRoute(cmdCtx),
		"gobgp/delete-route": DeleteRoute(cmdCtx),
		"gobgp/routes":       GoBGPRoutesCmd(cmdCtx),
	}
}

func nextParam(s string) (string, int, error) {
	var param string

	if !strings.HasPrefix(s, "[") {
		return "", 0, fmt.Errorf("expected parameter to be enclosed in '[]', got: %s", s)
	}

	foundEnd := false
	for _, r := range s[1:] {
		if r == ']' {
			foundEnd = true
			break
		}
		param = param + string(r)
	}

	if !foundEnd {
		return "", 0, fmt.Errorf("expected parameter to be enclosed in '[]', got: %s", s)
	}

	return param, len(param) + 2, nil
}

// parseEVPNRT5Prefix parses the EVPN RT5 prefix
// [RD][ESI][ETag][Prefix][GWIP][VNI] and returns it as a
// bgp.AddrPrefixInterface.
func parseEVPNRT5Prefix(s string) (bgp.AddrPrefixInterface, error) {
	param, n, err := nextParam(s)
	if err != nil {
		return nil, fmt.Errorf("failed to extract RD string: %w", err)
	}

	rd, err := bgp.ParseRouteDistinguisher(param)
	if err != nil {
		return nil, fmt.Errorf("invalid RD in EVPN prefix: %w", err)
	}

	sub := s[n:]
	param, n, err = nextParam(sub)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ESI string: %w", err)
	}

	if param != "single-homed" {
		return nil, fmt.Errorf("unsupported ESI in EVPN prefix (must be 'single-homed'): %s", param)
	}

	esi, err := bgp.ParseEthernetSegmentIdentifier([]string{param})
	if err != nil {
		return nil, fmt.Errorf("invalid ESI in EVPN prefix: %w", err)
	}

	sub = sub[n:]
	param, n, err = nextParam(sub)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ETag string: %w", err)
	}

	eTag, err := strconv.ParseUint(param, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid ETag in EVPN prefix: %w", err)
	}

	sub = sub[n:]
	param, n, err = nextParam(sub)
	if err != nil {
		return nil, fmt.Errorf("failed to extract Prefix string: %w", err)
	}

	prefix, err := netip.ParsePrefix(param)
	if err != nil {
		return nil, fmt.Errorf("invalid Prefix in EVPN prefix: %w", err)
	}

	sub = sub[n:]
	param, n, err = nextParam(sub)
	if err != nil {
		return nil, fmt.Errorf("failed to extract GatewayIP string: %w", err)
	}

	gwip, err := netip.ParseAddr(param)
	if err != nil {
		return nil, fmt.Errorf("invalid GatewayIP in EVPN prefix: %w", err)
	}

	sub = sub[n:]
	param, _, err = nextParam(sub)
	if err != nil {
		return nil, fmt.Errorf("failed to extract VNI string: %w", err)
	}

	vni, err := strconv.ParseUint(param, 10, 24)
	if err != nil {
		return nil, fmt.Errorf("invalid VNI in EVPN prefix: %w", err)
	}

	return bgp.NewEVPNIPPrefixRoute(
		rd,
		esi,
		uint32(eTag),
		uint8(prefix.Bits()),
		prefix.Addr().String(),
		gwip.String(),
		uint32(vni),
	), nil
}

func parsePrefix(s string) (bgp.AddrPrefixInterface, error) {
	// First try to interpret as an IPv4 or IPv6 prefix
	if prefix, err := netip.ParsePrefix(s); err == nil {
		if prefix.Addr().Is4() {
			return bgp.NewIPAddrPrefix(uint8(prefix.Bits()), prefix.Addr().String()), nil
		}
		return bgp.NewIPv6AddrPrefix(uint8(prefix.Bits()), prefix.Addr().String()), nil
	}

	if strings.HasPrefix(s, "EVPN") {
		sub := s[4:]

		param, n, err := nextParam(sub)
		if err != nil {
			return nil, fmt.Errorf("failed to extract RD string: %w", err)
		}

		typ, err := strconv.ParseUint(param, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid Route Type in EVPN prefix: %w", err)
		}
		if typ != 5 {
			return nil, fmt.Errorf("unsupported Route Type in EVPN prefix: %d", typ)
		}

		return parseEVPNRT5Prefix(sub[n:])
	}

	return nil, fmt.Errorf("invalid prefix format: %s", s)
}

// AddRoute adds a route to the GoBGP RIB.
func AddRoute(cmdCtx *commands.GoBGPCmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Adds a route to the GoBGP RIB",
			Args:    "prefix [nexthop] [llnexthop]",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP(
					commands.ServerNameFlag,
					commands.ServerNameFlagShort,
					"",
					"Name of the GoBGP server instance. Can be omitted if only one instance is active.",
				)
				fs.StringSliceP(
					communitiesFlag,
					communitiesFlagShort,
					nil,
					"BGP communities (standard / large / extended) to be associated with the route. Multiple comma-separated values are accepted.",
				)
			},
			Detail: []string{
				"Adds a route to the GoBGP RIB.",
				"",
				"'Prefix' is one of the following formats:",
				"  - IPv4 prefix (e.g. 10.0.0.0/24)",
				"  - IPv6 prefix (e.g. 2001:db8::/32)",
				"  - EVPN RT5 prefix EVPN[5][RD][ESI][ETag][Prefix][GWIP][VNI]",
				"    - RD: Route Distinguisher in any format",
				"    - ESI: Ethernet Segment Identifier, only 'single-homed' is supported at this point",
				"    - ETag: Ethernet Tag ID, a 32-bit unsigned integer",
				"    - Prefix: IPv4 or IPv6 prefix",
				"    - GWIP: Gateway IP address for the prefix",
				"    - VNI: VXLAN Network Identifier, a 24-bit unsigned integer",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 1 {
				return nil, fmt.Errorf("invalid command format, should be: 'gobgp/add-route prefix [nexthop] [llnexthop]'")
			}
			if len(args) > 3 {
				return nil, fmt.Errorf("invalid command format, too many arguments: 'gobgp/add-route prefix [nexthop] [llnexthop]'")
			}

			nlri, err := parsePrefix(args[0])
			if err != nil {
				return nil, fmt.Errorf("invalid prefix: %s: %w", args[0], err)
			}

			var nexthop, llnexthop netip.Addr
			if len(args) >= 2 {
				nexthop, err = netip.ParseAddr(args[1])
				if err != nil {
					return nil, fmt.Errorf("invalid nexthop: %s", args[1])
				}
			}
			if len(args) >= 3 {
				llnexthop, err = netip.ParseAddr(args[2])
				if err != nil {
					return nil, fmt.Errorf("invalid link-local nexthop: %s", args[2])
				}
			}

			return func(*script.State) (stdout, stderr string, err error) {
				goBGPServer, err := commands.GetGoBGPServer(s, cmdCtx)
				if err != nil {
					return "", "", fmt.Errorf("failed to get GoBGP server: %w", err)
				}

				originAttr := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP)

				var path *gobgpapi.Path
				switch {
				case len(args) == 1:
					// Defaulting case. Keep the
					// compatibility with the existing
					// behavior.
					var p *types.Path
					switch nlri := nlri.(type) {
					case *bgp.IPAddrPrefix:
						p = &types.Path{
							NLRI: nlri,
							PathAttributes: []bgp.PathAttributeInterface{
								originAttr,
								bgp.NewPathAttributeNextHop("0.0.0.0"),
							},
						}
					case *bgp.IPv6AddrPrefix:
						p = &types.Path{
							NLRI: nlri,
							PathAttributes: []bgp.PathAttributeInterface{
								originAttr,
								bgp.NewPathAttributeMpReachNLRI("::", []bgp.AddrPrefixInterface{nlri}),
							},
						}
					case *bgp.EVPNNLRI:
						p = &types.Path{
							NLRI: nlri,
							PathAttributes: []bgp.PathAttributeInterface{
								originAttr,
							},
						}
						rt5 := nlri.RouteTypeData.(*bgp.EVPNIPPrefixRoute)
						if rt5.IPPrefix.To4() != nil {
							p.PathAttributes = append(
								p.PathAttributes,
								bgp.NewPathAttributeMpReachNLRI("0.0.0.0", []bgp.AddrPrefixInterface{nlri}),
							)
						} else {
							p.PathAttributes = append(
								p.PathAttributes,
								bgp.NewPathAttributeMpReachNLRI("::", []bgp.AddrPrefixInterface{nlri}),
							)
						}
					default:
						return "", "", fmt.Errorf("unsupported NLRI type: %T", nlri)
					}
					path, err = gobgp.ToGoBGPPath(p)
					if err != nil {
						return "", "", fmt.Errorf("failed to convert prefix to GoBGP path: %w", err)
					}
				case len(args) == 2:
					if nlri.AFI() == bgp.AFI_IP && nexthop.Is4() {
						// v4 prefix with v4 nexthop.
						// Use regular NEXTHOP
						// attribute.
						nextHopAttr := bgp.NewPathAttributeNextHop(nexthop.String())
						path, err = gobgp.ToGoBGPPath(&types.Path{
							NLRI: nlri,
							PathAttributes: []bgp.PathAttributeInterface{
								originAttr,
								nextHopAttr,
							},
						})
						if err != nil {
							return "", "", fmt.Errorf("failed to convert prefix and nexthop to GoBGP path: %w", err)
						}
					} else {
						// Other cases (v4 prefix with
						// v6 nexthop, v6 prefix with v6
						// nexthop) are encoded using
						// MP_REACH_NLRI attribute.
						mpReachNLRIAttr := bgp.NewPathAttributeMpReachNLRI(nexthop.String(), []bgp.AddrPrefixInterface{nlri})
						path, err = gobgp.ToGoBGPPath(&types.Path{
							NLRI: nlri,
							PathAttributes: []bgp.PathAttributeInterface{
								originAttr,
								mpReachNLRIAttr,
							},
						})
						if err != nil {
							return "", "", fmt.Errorf("failed to convert prefix and nexthop to GoBGP path: %w", err)
						}
					}
				case len(args) >= 3:
					// Link-local nexthop is only usable
					// with MP_REACH_NLRI attribute.
					mpReachNLRIAttr := bgp.NewPathAttributeMpReachNLRI(nexthop.String(), []bgp.AddrPrefixInterface{nlri})
					mpReachNLRIAttr.LinkLocalNexthop = net.ParseIP(llnexthop.String())
					path, err = gobgp.ToGoBGPPath(&types.Path{
						NLRI: nlri,
						PathAttributes: []bgp.PathAttributeInterface{
							originAttr,
							mpReachNLRIAttr,
						},
					})
					if err != nil {
						return "", "", fmt.Errorf("failed to convert prefix and nexthops to GoBGP path: %w", err)
					}
				}

				commValues, err := s.Flags.GetStringSlice(communitiesFlag)
				if err != nil {
					return "", "", err
				}
				var (
					communities         []uint32
					largeCommunities    []*bgp.LargeCommunity
					extendedCommunities []bgp.ExtendedCommunityInterface
				)
				for _, community := range commValues {
					// First check the extended community
					// prefixes.
					switch {
					case strings.HasPrefix(community, "rt:"):
						rt, err := bgp.ParseRouteTarget(community[3:])
						if err != nil {
							return "", "", fmt.Errorf("invalid RT format: %w", err)
						}
						extendedCommunities = append(extendedCommunities, rt)
						continue

					case strings.HasPrefix(community, "rtrmac:"):
						rtrmac := bgp.NewRoutersMacExtended(community[7:])
						if rtrmac == nil {
							return "", "", fmt.Errorf("invalid Router's MAC format: %s", community[7:])
						}
						extendedCommunities = append(extendedCommunities, rtrmac)
						continue

					case strings.HasPrefix(community, "encap:"):
						encap, err := bgp.ParseExtendedCommunity(bgp.EC_SUBTYPE_ENCAPSULATION, community[6:])
						if encap == nil {
							return "", "", fmt.Errorf("invalid Encap format: %w", err)
						}
						extendedCommunities = append(extendedCommunities, encap)
						continue
					}

					elems := strings.Split(community, ":")
					if len(elems) == 2 {
						fst, _ := strconv.ParseUint(elems[0], 10, 16)
						snd, _ := strconv.ParseUint(elems[1], 10, 16)
						communities = append(communities, uint32(fst<<16|snd))
					} else if len(elems) == 3 {
						fst, _ := strconv.ParseUint(elems[0], 10, 32)
						snd, _ := strconv.ParseUint(elems[1], 10, 32)
						trd, _ := strconv.ParseUint(elems[2], 10, 32)
						largeCommunities = append(largeCommunities, &bgp.LargeCommunity{ASN: uint32(fst), LocalData1: uint32(snd), LocalData2: uint32(trd)})
					} else {
						return "", "", fmt.Errorf("invalid communities value")
					}
				}
				if len(communities) > 0 || len(largeCommunities) > 0 || len(extendedCommunities) > 0 {
					var pathAttrs []bgp.PathAttributeInterface
					if len(communities) > 0 {
						pathAttrs = append(pathAttrs, bgp.NewPathAttributeCommunities(communities))
					}
					if len(largeCommunities) > 0 {
						pathAttrs = append(pathAttrs, bgp.NewPathAttributeLargeCommunities(largeCommunities))
					}
					if len(extendedCommunities) > 0 {
						pathAttrs = append(pathAttrs, bgp.NewPathAttributeExtendedCommunities(extendedCommunities))
					}
					pattrs, err := apiutil.MarshalPathAttributes(pathAttrs)
					if err != nil {
						return "", "", fmt.Errorf("failed to convert PathAttribute: %w", err)
					}
					path.Pattrs = append(path.Pattrs, pattrs...)
				}

				if _, err := goBGPServer.AddPath(
					s.Context(),
					&gobgpapi.AddPathRequest{
						TableType: gobgpapi.TableType_LOCAL,
						Path:      path,
					},
				); err != nil {
					return "", "", fmt.Errorf("failed to add path: %w", err)
				}

				return "Successfully added route: " + args[0], "", nil
			}, nil
		},
	)
}

// DeleteRoute deletes a route to the GoBGP RIB.
func DeleteRoute(cmdCtx *commands.GoBGPCmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Deletes a route to the GoBGP RIB",
			Args:    "prefix",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP(
					commands.ServerNameFlag,
					commands.ServerNameFlagShort,
					"",
					"Name of the GoBGP server instance. Can be omitted if only one instance is active.",
				)
			},
			Detail: []string{
				"Deletes a route to the GoBGP RIB.",
				"",
				"'Prefix' is IPv4 or IPv6 prefix.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 1 {
				return nil, fmt.Errorf("invalid command format, should be: 'gobgp/delete-route prefix nexthop'")
			}
			nlri, err := parsePrefix(args[0])
			if err != nil {
				return nil, fmt.Errorf("invalid prefix: %s: %w", args[0], err)
			}
			return func(*script.State) (stdout, stderr string, err error) {
				goBGPServer, err := commands.GetGoBGPServer(s, cmdCtx)
				if err != nil {
					return "", "", fmt.Errorf("failed to get GoBGP server: %w", err)
				}

				path, err := gobgp.ToGoBGPPath(&types.Path{
					NLRI: nlri,
					PathAttributes: []bgp.PathAttributeInterface{
						bgp.NewPathAttributeMpReachNLRI("::", []bgp.AddrPrefixInterface{nlri}),
					},
				})
				if err != nil {
					return "", "", fmt.Errorf("failed to convert prefix to GoBGP path: %w", err)
				}

				if err := goBGPServer.DeletePath(
					s.Context(),
					&gobgpapi.DeletePathRequest{
						TableType: gobgpapi.TableType_LOCAL,
						Path:      path,
						Family:    path.Family,
					},
				); err != nil {
					return "", "", fmt.Errorf("failed to delete path: %w", err)
				}

				return "Successfully deleted route: " + args[0], "", nil
			}, nil
		},
	)
}

func GoBGPRoutesCmd(cmdCtx *commands.GoBGPCmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List routes on the GoBGP server",
			Args:    "[afi] [safi]",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP(commands.ServerNameFlag, commands.ServerNameFlagShort, "", "Name of the GoBGP server instance. Can be omitted if only one instance is active.")
				ceeCommands.AddOutFileFlag(fs)
			},
			Detail: []string{
				"List all routes in the global RIB on the GoBGP server",
				"",
				"'afi' is Address Family Indicator, defaults to 'ipv4'.",
				"'safi' is Subsequent Address Family Identifier, defaults to 'unicast'.",
				"If there are multiple server instances configured, the server-asn flag needs to be specified.",
			},
		},
		func(s *script.State, args ...string) (waitFunc script.WaitFunc, err error) {
			gobgpServer, err := commands.GetGoBGPServer(s, cmdCtx)
			if err != nil {
				return nil, err
			}
			return func(*script.State) (stdout, stderr string, err error) {
				w, buf, f, err := ceeCommands.GetCmdWriter(s)
				if err != nil {
					return "", "", err
				}
				tw := ceeCommands.GetCmdTabWriter(w)
				if f != nil {
					defer f.Close()
				}

				req := &gobgpapi.ListPathRequest{
					TableType: gobgpapi.TableType_GLOBAL,
					Family: &gobgpapi.Family{
						Afi:  gobgpapi.Family_AFI_IP,
						Safi: gobgpapi.Family_SAFI_UNICAST,
					},
				}
				if len(args) > 0 && args[0] != "" {
					req.Family.Afi = gobgpapi.Family_Afi(types.ParseAfi(args[0]))
				}
				if len(args) > 1 && args[1] != "" {
					req.Family.Safi = gobgpapi.Family_Safi(types.ParseSafi(args[1]))
				}
				var paths []*gobgpapi.Destination
				err = gobgpServer.ListPath(s.Context(), req, func(dst *gobgpapi.Destination) {
					paths = append(paths, dst)
				})
				sort.Slice(paths, func(i, j int) bool {
					return paths[i].String() < paths[j].String()
				})

				printPathHeader(tw)
				for _, path := range paths {
					printPath(tw, path)
				}
				tw.Flush()
				return buf.String(), "", err
			}, nil
		},
	)
}

func printPathHeader(w *tabwriter.Writer) {
	fmt.Fprintln(w, "Prefix\tNextHop\tAttrs")
}

func printPath(w *tabwriter.Writer, dst *gobgpapi.Destination) {
	aPaths, _ := gobgp.ToAgentPaths(dst.Paths)
	sort.Slice(aPaths, func(i, j int) bool {
		return fmt.Sprint(aPaths[i].PathAttributes) < fmt.Sprint(aPaths[j].PathAttributes)
	})
	for _, path := range aPaths {
		fmt.Fprintf(w, "%s\t%s\t%s\n", dst.Prefix, api.NextHopFromPathAttributes(path.PathAttributes), ceeCommands.FormatPathAttributes(path.PathAttributes))
	}
}
