package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"text/tabwriter"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"
	"go.yaml.in/yaml/v3"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcmap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"

	"google.golang.org/grpc/connectivity"
)

var shellCommandsCell = cell.Module(
	"shell-commands",
	"Shell Commands",
	cell.Provide(scriptCommands),
)

type params struct {
	cell.In

	Config Config

	BPFIPCache bpfIPCache

	FQDNAgentClient   *fqdnAgentClient
	RemoteNameManager *remoteNameManager

	Watcher *rulesWatcher
}

func scriptCommands(p params) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"dnsproxy/config":     dumpConfigCmd(p),
		"dnsproxy/conn-state": logAgentConnectivityStateCmd(p),
		"dnsproxy/bpfipcache": dumpBPFIPCacheStatusCmd(p),
		"dnsproxy/rules":      dumpDNSProxyRulesCmd(p),
		"dnsproxy/selectors":  dumpSelectorStoreCmd(p),
		"dnsproxy/identities": dumpIdentityStoreCmd(p),
		"dnsproxy/endpoints":  dumpCachedEndpointsCmd(p),
		"dnsproxy/iplist":     dumpCachedIPsCmd(p),
	})
}

func dumpConfigCmd(p params) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Dumps the active configuration of DNS Proxy.",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("output", "o", "table", "Format to write output in (table, yaml or json)")
			},
			AutocompleteFlag: func(state *script.State, args []string, flag, cur string) []string {
				switch flag {
				case "output":
					return []string{"table", "yaml", "json"}
				}
				return nil
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			output, err := s.Flags.GetString("output")
			if err != nil {
				return nil, err
			}

			switch output {
			case "json":
				enc := json.NewEncoder(s.LogWriter())
				enc.SetIndent("", "  ")
				return nil, enc.Encode(p.Config)
			case "yaml":
				enc := yaml.NewEncoder(s.LogWriter())
				return nil, enc.Encode(p.Config)
			case "table":
				tw := tabwriter.NewWriter(s.LogWriter(), 5, 0, 3, ' ', 0)
				defer tw.Flush()

				if _, err := fmt.Fprintln(tw, "Name\tValue"); err != nil {
					return nil, err
				}
				fmt.Fprintln(tw, "----\t-----")

				cfgValue := reflect.ValueOf(p.Config)
				cfgType := cfgValue.Type()
				for i := range cfgValue.NumField() {
					cfgData := fmt.Sprintf("%s\t%v", cfgType.Field(i).Name, cfgValue.Field(i).Interface())
					if _, err := fmt.Fprintln(tw, cfgData); err != nil {
						return nil, err
					}
				}
				return nil, nil
			default:
				return nil, fmt.Errorf("unknown format %s", output)
			}
		},
	)
}

func logAgentConnectivityStateCmd(p params) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Logs the gRPC connection state between DNS Proxy and cilium-agent.",
			Flags: func(fs *pflag.FlagSet) {
				fs.BoolP("watch", "w", false, "Watch the changes in gRPC connection state")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			watch, err := s.Flags.GetBool("watch")
			if err != nil {
				return nil, err
			}

			conn := p.FQDNAgentClient.conn
			if conn == nil {
				return nil, errors.New("connection not initialized")
			}

			logConnectivityState := func(state connectivity.State) {
				var stateIcon string
				switch {
				case state == connectivity.Ready:
					stateIcon = "✅"
				case state == connectivity.Idle || state == connectivity.Connecting:
					stateIcon = "⚠️"
				case state == connectivity.TransientFailure || state == connectivity.Shutdown:
					stateIcon = "❌"
				default:
					s.Logf("Invalid Connectivity State: %s\n", state)
					return
				}

				s.Logf("[%s] %s %s\n", time.Now().Format(time.RFC3339), stateIcon, state.String())
			}

			for s.Context().Err() == nil {
				state := conn.GetState()
				logConnectivityState(state)

				if !watch {
					break
				}
				err = s.FlushLog()
				if err != nil {
					return nil, err
				}
				conn.WaitForStateChange(s.Context(), state)
			}

			return nil, nil
		},
	)
}

func dumpBPFIPCacheStatusCmd(p params) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Dump status of BPF IPCache map managed by DNS Proxy for offline mode.",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if !p.Config.EnableOfflineMode {
				s.Logf("Offline Mode Disabled\n")
				return nil, nil
			}

			ipc, agentStartTime, writesEnabled := p.BPFIPCache.getInfo()
			if ipc == nil || !ipc.IsOpen() {
				s.Logf("BPF IPCache map not opened: %s [WritesEnabled: %t]\n", ipcmap.Name, writesEnabled)
				return nil, nil
			}

			tw := tabwriter.NewWriter(s.LogWriter(), 5, 0, 3, ' ', 0)
			defer tw.Flush()

			fmt.Fprintf(tw, "Map Name\t%s\n", ipc.Name())
			fmt.Fprintf(tw, "Map FileDescriptor\t%d\n", ipc.FD())
			fmt.Fprintf(tw, "Map MaxEntries\t%d\n", ipc.MaxEntries())

			fmt.Fprintf(tw, "Writes Enabled\t%t\n", writesEnabled)
			fmt.Fprintf(tw, "Current Agent StartTime\t%s\n", agentStartTime.Format(time.RFC3339))

			return nil, nil
		},
	)
}

func dumpDNSProxyRulesCmd(p params) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Dump allowed FQDN rules from DNS Proxy instance.",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("output", "o", "table", "Format to write output in (table, yaml or json)")
			},
			AutocompleteFlag: func(state *script.State, args []string, flag, cur string) []string {
				switch flag {
				case "output":
					return []string{"table", "yaml", "json"}
				}
				return nil
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if p.Watcher.proxy == nil {
				return nil, errors.New("dns proxy instance not configured")
			}

			output, err := s.Flags.GetString("output")
			if err != nil {
				return nil, err
			}

			rulesDump := p.Watcher.proxy.DumpRules()
			switch output {
			case "json":
				enc := json.NewEncoder(s.LogWriter())
				enc.SetIndent("", "  ")
				return nil, enc.Encode(rulesDump)
			case "yaml":
				enc := yaml.NewEncoder(s.LogWriter())
				return nil, enc.Encode(rulesDump)
			case "table":
			default:
				return nil, fmt.Errorf("unknown format %s", output)
			}

			tw := tabwriter.NewWriter(s.LogWriter(), 5, 0, 3, ' ', 0)
			defer tw.Flush()

			if _, err := fmt.Fprintln(tw, "EndpointID\tPort\tProto\tSelector\tRegex\tIdentities"); err != nil {
				return nil, err
			}
			fmt.Fprintln(tw, "----------\t----\t-----\t--------\t-----\t----------")

			for _, fqdnRules := range rulesDump {
				first := true
				epPortProto := fmt.Sprintf("%d\t%d\t%s", fqdnRules.EndpointID, fqdnRules.DestPort, u8proto.U8proto(fqdnRules.DestProto).String())

				for selector, ids := range fqdnRules.Rules.SelectorIdentitiesMapping {
					row := ""
					firstId := true
					selectorRegex := fqdnRules.Rules.SelectorRegexMapping[selector]

					if first {
						row = fmt.Sprintf("%s\t%s\t%s", epPortProto, selector, selectorRegex)
					} else {
						row = "\t\t\t\t"
					}

					if len(ids.List) == 0 {
						if _, err := fmt.Fprintf(tw, "%s\t\n", row); err != nil {
							return nil, err
						}
					} else {
						for _, id := range ids.List {
							if firstId {
								if _, err := fmt.Fprintf(tw, "%s\t%d\n", row, id); err != nil {
									return nil, err
								}
								firstId = false
							} else {
								if _, err := fmt.Fprintf(tw, "\t\t\t\t\t%d\n", id); err != nil {
									return nil, err
								}
							}
						}
					}
				}
			}

			return nil, nil
		},
	)
}

func dumpSelectorStoreCmd(p params) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Dump FQDN selectors state",
			Detail: []string{
				"Dump FQDN selectors state received from cilium agent.",
				"Selector state sync is only started when offline mode is enabled.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			tw := tabwriter.NewWriter(s.LogWriter(), 5, 0, 3, ' ', 0)
			defer tw.Flush()

			if _, err := fmt.Fprintln(tw, "Match\tRegex"); err != nil {
				return nil, err
			}
			fmt.Fprintln(tw, "-----\t-----")

			for sel, regex := range p.RemoteNameManager.selectors.selectors {
				match := sel.MatchName
				if len(sel.MatchName) == 0 {
					match = sel.MatchPattern
				}

				selector := fmt.Sprintf("%s\t%s", match, regex.String())
				if _, err := fmt.Fprintln(tw, selector); err != nil {
					return nil, err
				}
			}
			return nil, nil
		},
	)
}

func dumpIdentityStoreCmd(p params) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Dump FQDN local Identities synced from cilium-agent",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			tw := tabwriter.NewWriter(s.LogWriter(), 5, 0, 3, ' ', 0)
			defer tw.Flush()

			if _, err := fmt.Fprintln(tw, "Identity\tLabels"); err != nil {
				return nil, err
			}
			fmt.Fprintln(tw, "--------\t------")

			for id, labelArray := range p.RemoteNameManager.identities.byID {
				first := true
				for _, label := range labelArray {
					var row string
					if first {
						row = fmt.Sprintf("%d\t%s", id, label.String())
						first = false
					} else {
						row = fmt.Sprintf("\t%s", label.String())
					}

					if _, err := fmt.Fprintln(tw, row); err != nil {
						return nil, err
					}
				}
			}
			return nil, nil
		},
	)
}

func dumpCachedEndpointsCmd(p params) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Dump cached endpoint info synced from cilium-agent.",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			tw := tabwriter.NewWriter(s.LogWriter(), 5, 0, 3, ' ', 0)
			defer tw.Flush()

			if _, err := fmt.Fprintln(tw, "IP\tEndpointID\tSecurityID\tNamespace\tPod"); err != nil {
				return nil, err
			}
			fmt.Fprintln(tw, "--\t----------\t----------\t---------\t---")

			p.RemoteNameManager.cache.endpointByIP.ForEach(func(addr netip.Addr, ep *endpoint.Endpoint) {
				epInfo := fmt.Sprintf("%s\t%d\t%d\t%s\t%s", addr.String(), ep.ID, ep.SecurityIdentity.ID, ep.K8sNamespace, ep.K8sPodName)
				fmt.Fprintln(tw, epInfo)
			})

			return nil, nil
		},
	)
}

func dumpCachedIPsCmd(p params) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Dump cached ip to identity mappings synced from cilium-agent.",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			tw := tabwriter.NewWriter(s.LogWriter(), 5, 0, 3, ' ', 0)
			defer tw.Flush()

			if _, err := fmt.Fprintln(tw, "IP\tSource\tIdentity"); err != nil {
				return nil, err
			}
			fmt.Fprintln(tw, "--\t------\t--------")

			p.RemoteNameManager.cache.identityByIP.ForEach(func(addr netip.Addr, id ipcache.Identity) {
				idInfo := fmt.Sprintf("%s\t%s\t%d", addr.String(), id.Source, id.ID)
				fmt.Fprintln(tw, idInfo)
			})

			return nil, nil
		},
	)
}
