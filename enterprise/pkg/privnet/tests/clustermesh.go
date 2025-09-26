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
	"fmt"
	"os"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/enterprise/pkg/privnet/kvstore"
	"github.com/cilium/cilium/enterprise/pkg/privnet/observers"
	"github.com/cilium/cilium/pkg/kvstore/store"
)

var ClusterMeshObservers = cell.Group(
	cell.Provide(
		func(obs *observers.PrivateNetworkEndpoints) uhive.ScriptCmdsOut {
			return uhive.NewScriptCmds(
				cmObserver[*kvstore.ValidatingEndpoint]{
					name: "endpoints",
					kc:   kvstore.EndpointKeyCreator(),
					obs:  obs,
				}.cmds(),
			)
		},
	),
)

type cmObserver[T store.Key] struct {
	name string
	kc   store.KeyCreator
	obs  interface {
		store.Observer
		OnSync()
	}
}

func (obs cmObserver[T]) cmds() map[string]script.Cmd {
	return map[string]script.Cmd{
		fmt.Sprintf("clustermesh/%s/upsert", obs.name): obs.upsertDelete(false),
		fmt.Sprintf("clustermesh/%s/delete", obs.name): obs.upsertDelete(true),
		fmt.Sprintf("clustermesh/%s/sync", obs.name):   obs.sync(),
	}
}

func (obs cmObserver[T]) upsertDelete(delete bool) script.Cmd {
	str := "upsert"
	if delete {
		str = "delete"
	}

	return script.Command(
		script.CmdUsage{
			Summary: fmt.Sprintf("%s clustermesh %s", str, obs.name),
			Args:    "key value-file",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("%w: expected key and value file", script.ErrUsage)
			}

			b, err := os.ReadFile(s.Path(args[1]))
			if err != nil {
				return nil, fmt.Errorf("could not read %q: %w", s.Path(args[1]), err)
			}

			entry := obs.kc()
			if err := entry.Unmarshal(args[0], b); err != nil {
				return nil, fmt.Errorf("could not unmarshal %q: %w", s.Path(args[1]), err)
			}

			if delete {
				obs.obs.OnDelete(entry)
			} else {
				obs.obs.OnUpdate(entry)
			}

			return nil, nil
		},
	)
}

func (obs cmObserver[t]) sync() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: fmt.Sprintf("mark the clustermesh %s observer as synchronized", obs.name),
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			obs.obs.OnSync()
			return nil, nil
		},
	)
}
