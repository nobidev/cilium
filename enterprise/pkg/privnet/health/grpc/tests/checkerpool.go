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
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/privnet/health"
	"github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/checker"
	"github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

var CheckerPoolCell = cell.Group(
	cell.Provide(
		newCheckerPool,
		(*CheckerPool).Commands,
	),
)

type CheckerPool struct {
	log *slog.Logger
	lc  cell.Lifecycle
	jg  job.Group
	db  *statedb.DB

	cfg     config.Config
	factory checker.ConnFactoryFn
	pool    map[string]*Checker
	started bool
}

func newCheckerPool(in struct {
	cell.In

	Log       *slog.Logger
	Lifecycle cell.Lifecycle
	JobGroup  job.Group
	DB        *statedb.DB

	Config  config.Config
	Factory checker.ConnFactoryFn
}) *CheckerPool {
	cp := &CheckerPool{
		log: in.Log,
		lc:  in.Lifecycle,
		jg:  in.JobGroup,
		db:  in.DB,

		cfg:     in.Config,
		factory: in.Factory,
		pool:    make(map[string]*Checker),
	}

	in.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			cp.started = true
			return nil
		},
	})

	return cp
}

func (cp *CheckerPool) Commands() hive.ScriptCmdsOut {
	return hive.NewScriptCmds(
		map[string]script.Cmd{
			"checkerpool/new": cp.checkerInstanceCmd("Create a new checker instance", cp.new),

			"checkerpool/register": cp.checkerNodeNetworkCmd(
				"Register a node, network pair for a checker", cp.register),
			"checkerpool/deregister": cp.checkerNodeNetworkCmd(
				"Deregister a node, network pair for a checker", cp.deregister),
			"checkerpool/activate": cp.checkerNodeNetworkCmd(
				"Activate a node, network pair for a checker", cp.activate),
			"checkerpool/deactivate": cp.checkerNodeNetworkCmd(
				"Deactivate a node, network pair for a checker", cp.deactivate),

			"checkerpool/synced": cp.checkerCmd("Signal initialization to a checker", cp.synced),
		},
	)
}

func (cp *CheckerPool) checkerInstanceCmd(usage string, do func(string, Instance) error) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: usage,
			Args:    "checker cluster/node",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("%w: expected checker cluster/node", script.ErrUsage)
			}

			inst, err := NewInstance(args[1])
			if err != nil {
				return nil, fmt.Errorf("%w: %w", script.ErrUsage, err)
			}

			return nil, do(args[0], inst)
		},
	)
}

func (cp *CheckerPool) checkerNodeNetworkCmd(usage string, do func(string, tables.INBNode, tables.NetworkName) error) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: usage,
			Args:    "checker cluster/node network",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 3 {
				return nil, fmt.Errorf("%w: expected checker cluster/node network", script.ErrUsage)
			}

			node, err := NewInstance(args[1])
			if err != nil {
				return nil, fmt.Errorf("%w: %w", script.ErrUsage, err)
			}

			return nil, do(args[0], node.ToINBNode(), tables.NetworkName(args[2]))
		},
	)
}

func (cp *CheckerPool) checkerCmd(usage string, do func(string) error) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: usage,
			Args:    "checker",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("%w: expected checker", script.ErrUsage)
			}

			return nil, do(args[0])
		},
	)
}

func (cp *CheckerPool) new(name string, inst Instance) error {
	const loginst = "instance"

	if cp.started {
		return errors.New("hive already started")
	}

	if _, found := cp.pool[name]; found {
		return errors.New("already exists")
	}

	// Create a separate table for every checker, for convenience.
	state, err := newTable(cp.db, "test-observed-state-"+name)
	if err != nil {
		return fmt.Errorf("creating table: %w", err)
	}

	ln := checker.LocalNode{Cluster: string(inst.Cluster), Name: string(inst.Name)}
	c := &Checker{
		Checker: checker.New(
			cp.log.With(loginst, inst),
			cp.lc, cp.cfg, cp.factory, ln,
		),

		db:    cp.db,
		state: state,
	}

	wtx := cp.db.WriteTxn(c.state)
	init := c.state.RegisterInitializer(wtx, "test-observer")
	wtx.Commit()

	cp.jg.Add(
		job.Observer(
			"test-health-checker-observer-"+name,
			func(ctx context.Context, buf health.Events) error {
				wtx := c.db.WriteTxn(c.state)

				for _, ev := range buf {
					switch ev.EventKind {
					case health.EventKindUpsert:
						entry := InstanceNetwork{
							Instance: Instance{
								Cluster: ev.Object.Node.Cluster,
								Name:    ev.Object.Node.Name,
							}, Network: ev.Object.Network,
						}

						entry, _, found := c.state.Get(wtx, byObject(entry))
						if !found {
							continue
						}

						entry.Health = ev.Object.State
						c.state.Insert(wtx, entry)

					case health.EventKindSync:
						init(wtx)
					}
				}

				wtx.Commit()
				return nil
			}, c.Checker,
		),
	)

	cp.pool[name] = c
	return nil
}

func (cp *CheckerPool) register(name string, target tables.INBNode, network tables.NetworkName) error {
	return cp.do(name, func(c *Checker) error { return c.Register(target, network) })
}

func (cp *CheckerPool) deregister(name string, target tables.INBNode, network tables.NetworkName) error {
	return cp.do(name, func(c *Checker) error { return c.Deregister(target, network) })
}

func (cp *CheckerPool) activate(name string, target tables.INBNode, network tables.NetworkName) error {
	return cp.do(name, func(c *Checker) error { return c.Activate(target, network) })
}

func (cp *CheckerPool) deactivate(name string, target tables.INBNode, network tables.NetworkName) error {
	return cp.do(name, func(c *Checker) error { return c.Deactivate(target, network) })
}

func (cp *CheckerPool) synced(name string) error {
	return cp.do(name, func(c *Checker) error {
		c.Synced()
		return nil
	})
}

func (cp *CheckerPool) do(name string, fn func(*Checker) error) error {
	checker, found := cp.pool[name]
	if !found {
		return errors.New("not found")
	}

	return fn(checker)
}

type Checker struct {
	health.Checker

	db    *statedb.DB
	state statedb.RWTable[InstanceNetwork]
}

func (c *Checker) Register(node tables.INBNode, network tables.NetworkName) error {
	wtx := c.db.WriteTxn(c.state)
	c.state.Modify(wtx, InstanceNetwork{Instance: NewInstanceFromINBNode(node), Network: network},
		// Don't mutate anything if the entry already exists.
		func(old, _ InstanceNetwork) InstanceNetwork { return old })
	wtx.Commit()

	return c.Checker.Register(node, network)
}

func (c *Checker) Deregister(node tables.INBNode, network tables.NetworkName) error {
	wtx := c.db.WriteTxn(c.state)
	c.state.Delete(wtx, InstanceNetwork{Instance: NewInstanceFromINBNode(node), Network: network})
	wtx.Commit()

	return c.Checker.Deregister(node, network)
}
