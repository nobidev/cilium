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
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"text/tabwriter"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/enterprise/pkg/privnet/policy"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	policyutils "github.com/cilium/cilium/pkg/policy/utils"
	cslices "github.com/cilium/cilium/pkg/slices"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

func mockPolicyCell(t testing.TB) cell.Cell {
	t.Helper()

	return cell.Group(
		cell.Provide(
			newMockIPCacher,
			newMockPolicyImporter,

			func(alloc cache.IdentityAllocator) uhive.ScriptCmdsOut {
				return uhive.NewScriptCmds(map[string]script.Cmd{
					"privnet/allocate-identity": allocateIdentity(alloc),
					"privnet/release-identity":  releaseIdentity(alloc),
					"privnet/list-identities":   listIdentities(alloc),
				})
			},
		),

		cell.Invoke(
			startFakeCNPWatcher,
			startFakeCCGWatcher,
		),
	)
}

type mockIPCacher struct{}

func (m *mockIPCacher) UpsertMetadataBatch(updates ...ipcache.MU) (revision uint64) {
	return 0
}

func (m *mockIPCacher) RemoveMetadataBatch(updates ...ipcache.MU) (revision uint64) {
	return 0
}

func (m *mockIPCacher) WaitForRevision(ctx context.Context, rev uint64) error {
	return nil
}

func newMockIPCacher() policycell.IPCacher {
	return &mockIPCacher{}
}

type mockPolicyImporter struct{}

func (m *mockPolicyImporter) UpdatePolicy(update *policytypes.PolicyUpdate) {}

func newMockPolicyImporter() policycell.PolicyImporter {
	return &mockPolicyImporter{}
}

func startFakeCNPWatcher(in struct {
	cell.In

	JobGroup    job.Group
	CNPResource resource.Resource[*cilium_api_v2.CiliumNetworkPolicy]
	Logger      *slog.Logger
	Importer    policycell.PolicyImporter
	Fence       k8sSyncFence
}) {
	cnpsSynced := make(chan struct{})
	in.Fence.Add("cnps-sycned", func(ctx context.Context) error {
		select {
		case <-cnpsSynced:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	in.JobGroup.Add(job.Observer("watch-cnps", func(ctx context.Context, event resource.Event[*cilium_api_v2.CiliumNetworkPolicy]) error {
		defer event.Done(nil)
		switch event.Kind {
		case resource.Upsert, resource.Delete:
			resourceID := ipcacheTypes.NewResourceID(
				ipcacheTypes.ResourceKindCNP,
				event.Object.Namespace,
				event.Object.Name,
			)

			var rules policytypes.PolicyEntries
			if event.Kind == resource.Upsert {
				apiRules, err := event.Object.Parse(in.Logger, cmtypes.PolicyAnyCluster)
				if err != nil {
					logging.Fatal(in.Logger, "Failed to parse CNP", logfields.Error, err)
					return nil
				}
				rules = policyutils.RulesToPolicyEntries(apiRules)
			}

			in.Importer.UpdatePolicy(&policytypes.PolicyUpdate{
				Rules:               rules,
				Resource:            resourceID,
				Source:              source.CustomResource,
				ProcessingStartTime: time.Now(),
				DoneChan:            nil,
			})
		case resource.Sync:
			close(cnpsSynced)
		}
		return nil
	}, in.CNPResource))
}

func startFakeCCGWatcher(in struct {
	cell.In

	JobGroup    job.Group
	CCGResource resource.Resource[*cilium_api_v2.CiliumCIDRGroup]
	Logger      *slog.Logger
	IPCacher    policycell.IPCacher
	Fence       k8sSyncFence
}) {
	ccgsSynced := make(chan struct{})
	in.Fence.Add("ccgs-sycned", func(ctx context.Context) error {
		select {
		case <-ccgsSynced:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	ccgPrefixes := policy.NewCIDRTracker()
	in.JobGroup.Add(job.Observer("watch-ccg", func(ctx context.Context, event resource.Event[*cilium_api_v2.CiliumCIDRGroup]) error {
		defer event.Done(nil)
		switch event.Kind {
		case resource.Upsert, resource.Delete:
			resourceID := ipcacheTypes.NewResourceID(
				ipcacheTypes.ResourceKindCIDRGroup,
				event.Object.Namespace,
				event.Object.Name,
			)

			// Note: We currently don't mock adding the CIDRGroup labels other than the group name,
			// as this approach is broken anyway, c.f. isovalent/cilium#9413
			lbl := api.LabelForCIDRGroupRef(event.Object.Name)
			lbls := labels.Labels{lbl.Key: lbl}

			var newPrefixes, oldPrefixes sets.Set[netip.Prefix]
			if event.Kind == resource.Upsert {
				newPrefixes = sets.New(
					cslices.Map(event.Object.Spec.ExternalCIDRs, func(in api.CIDR) netip.Prefix {
						return netip.MustParsePrefix(string(in))
					})...,
				)
			}
			oldPrefixes = ccgPrefixes.Swap(resourceID, newPrefixes)

			toUpsert := newPrefixes.Difference(oldPrefixes)
			upsertBatch := make([]ipcache.MU, 0, len(toUpsert))
			for prefix := range toUpsert {
				upsertBatch = append(upsertBatch, ipcache.MU{
					Prefix:   cmtypes.NewLocalPrefixCluster(prefix),
					Source:   source.CustomResource,
					Resource: resourceID,
					Metadata: []ipcache.IPMetadata{lbls},
				})
			}
			in.IPCacher.UpsertMetadataBatch(upsertBatch...)

			toDelete := oldPrefixes.Difference(newPrefixes)
			deleteBatch := make([]ipcache.MU, 0, len(toDelete))
			for prefix := range toDelete {
				deleteBatch = append(deleteBatch, ipcache.MU{
					Prefix:   cmtypes.NewLocalPrefixCluster(prefix),
					Source:   source.CustomResource,
					Resource: resourceID,
					Metadata: []ipcache.IPMetadata{labels.Labels{}},
				})
			}
			in.IPCacher.RemoveMetadataBatch(deleteBatch...)
		case resource.Sync:
			close(ccgsSynced)
		}
		return nil
	}, in.CCGResource))
}

func allocateIdentity(alloc cache.IdentityAllocator) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "allocate a Cilium security identity",
			Args:    "lbl1=v1 lbl2=v2 ...",
			Flags: func(fs *pflag.FlagSet) {
				fs.Uint32("nid", identity.IdentityUnknown.Uint32(), "Request specific numeric identity (if possible)")
				fs.StringP("output", "o", "", "output file name")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			out, err := s.Flags.GetString("output")
			if err != nil {
				return nil, fmt.Errorf("failed get output: %w", err)
			}

			nid, err := s.Flags.GetUint32("nid")
			if err != nil {
				return nil, fmt.Errorf("failed to parse nid flag: %w", err)
			}

			return func(s *script.State) (stdout string, stderr string, err error) {
				lbls := labels.ParseLabelArray(args...).Labels()
				id, _, err := alloc.AllocateIdentity(s.Context(), lbls, false, identity.NumericIdentity(nid))
				if err != nil {
					return stdout, stderr, fmt.Errorf("failed to allocate identity: %w", err)
				}

				result := fmt.Sprintf("%d\n", id.ID)
				if len(out) == 0 {
					stdout = result
				} else {
					err = os.WriteFile(s.Path(out), []byte(result), 0644)
					if err != nil {
						return stdout, stderr, fmt.Errorf("could not write %q: %w", s.Path(out), err)
					}
				}
				return stdout, stderr, nil
			}, nil
		},
	)
}

func releaseIdentity(alloc cache.IdentityAllocator) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "release a Cilium security identity",
			Args:    "<numeric-identity>",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("input", "i", "", "Read numeric identity from file")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			in, err := s.Flags.GetString("input")
			if err != nil {
				return nil, fmt.Errorf("failed get input: %w", err)
			}

			if len(in) == 0 && len(args) < 1 {
				return nil, fmt.Errorf("%w: expected numeric identity", script.ErrUsage)
			}

			return func(s *script.State) (stdout string, stderr string, err error) {
				var inputStr string
				if len(in) != 0 {
					b, err := os.ReadFile(s.Path(in))
					if err != nil {
						return stdout, stderr, fmt.Errorf("failed read input: %w", err)
					}
					inputStr = string(b)
				} else {
					inputStr = args[0]
				}

				nid, err := strconv.ParseUint(strings.TrimSpace(inputStr), 10, 32)
				if err != nil {
					return stdout, stderr, fmt.Errorf("failed to parse nid flag: %w", err)
				}

				_, err = alloc.Release(s.Context(), &identity.Identity{ID: identity.NumericIdentity(nid)}, false)
				if err != nil {
					return stdout, stderr, fmt.Errorf("failed to release identity: %w", err)
				}

				return stdout, stderr, nil
			}, nil
		},
	)
}

func listIdentities(alloc cache.IdentityAllocator) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List all Cilium security identities",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("output", "o", "", "output file name")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			out, err := s.Flags.GetString("output")
			if err != nil {
				return nil, fmt.Errorf("failed get output: %w", err)
			}

			return func(s *script.State) (stdout string, stderr string, err error) {
				identityMap := alloc.GetIdentityCache()
				identities := make(cache.IdentitiesModel, 0, len(identityMap))
				for nid, lbls := range identityMap {
					identities = append(identities, &models.Identity{
						ID:     int64(nid),
						Labels: lbls.GetModel(),
					})
				}
				sort.Slice(identities, identities.Less)

				b := new(bytes.Buffer)
				w := tabwriter.NewWriter(b, 2, 0, 3, ' ', 0)
				fmt.Fprintf(w, "ID\tLABELS\n")
				for _, identity := range identities {
					lbls := labels.NewLabelsFromModel(identity.Labels)
					first := true
					for _, lbl := range lbls.GetPrintableModel() {
						if first {
							fmt.Fprintf(w, "%d\t%s\n", identity.ID, lbl)
							first = false
						} else {
							fmt.Fprintf(w, "\t%s\n", lbl)
						}
					}
				}
				w.Flush()

				if len(out) > 0 {
					err = os.WriteFile(s.Path(out), b.Bytes(), 0644)
					if err != nil {
						return stdout, stderr, fmt.Errorf("could not write %q: %w", s.Path(out), err)
					}
				} else {
					stdout = b.String()
				}

				return stdout, stderr, nil
			}, nil
		},
	)
}
