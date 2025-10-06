// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package healthchecker

import (
	"container/heap"
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"golang.org/x/sync/errgroup"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// probeParallelism is the maximum number of parallel probes
	// (connections) to perform.
	probeParallelism = 100
)

type checkerParams struct {
	cell.In

	Config       Config
	LBConfig     loadbalancer.Config
	Log          *slog.Logger
	DB           *statedb.DB
	HealthChecks statedb.RWTable[*healthCheck]
}

func registerChecker(jg job.Group, p checkerParams) error {
	if !p.Config.EnableActiveLbHealthChecking {
		return nil
	}
	c := checker{p}
	jg.Add(job.OneShot("checker", c.run))
	return nil
}

type checker struct {
	checkerParams
}

func (c *checker) run(ctx context.Context, health cell.Health) error {
	wtxn := c.DB.WriteTxn(c.HealthChecks)
	changeIter, err := c.HealthChecks.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return err
	}

	rq := probeQueue{}
	items := map[healthCheckKey]*probeItem{}

	probeTimer := time.NewTimer(0)
	defer probeTimer.Stop()

	for {
		now := time.Now()

		// Collect the backends that are ready to be probed.
		toProbe := []*probeItem{}
		for len(rq) > 0 {
			untilNext := rq[0].probeAt.Sub(now)
			if untilNext > 0 {
				break
			}
			item := heap.Pop(&rq).(*probeItem)
			delete(items, item.hc.key())
			toProbe = append(toProbe, item)
		}

		// Perform the probing in parallel.
		g, probeCtx := errgroup.WithContext(ctx)
		g.SetLimit(probeParallelism)
		for _, item := range toProbe {
			g.Go(probeFunc(c.Log, c.DB, c.HealthChecks, probeCtx, item))
		}
		g.Wait()

		// Process the new or changed desired HealthChecks to queue up the
		// next round of probing. This both processes the changes from [controller]
		// and computes the next probe time based on the probe results from above.
		changes, watch := changeIter.Next(c.DB.ReadTxn())
		for change := range changes {
			hc := change.Object
			key := hc.key()
			if change.Deleted {
				if item, ok := items[key]; ok {
					heap.Remove(&rq, item.index)
					delete(items, key)
				}
				continue
			}
			item, ok := items[key]
			if !ok {
				item = &probeItem{}
				items[hc.key()] = item
			}
			item.hc = hc.clone()
			item.rev = change.Revision
			item.probeAt = hc.probeAt()
			heap.Push(&rq, item)
		}

		// Prime the timer for the next probe round. Round it up to a full
		// second.
		if len(rq) > 0 {
			probeTimer.Reset(min(time.Second, rq[0].probeAt.Sub(now)))
		}

		select {
		case <-ctx.Done():
			return nil
		case <-probeTimer.C:
		case <-watch:
		}
	}
}

type probeItem struct {
	hc      *healthCheck
	rev     statedb.Revision
	probeAt time.Time
	index   int
}

// probeQueue is a priority queue key'd on the next probe time. The
// next item to probe will be at index 0.
type probeQueue []*probeItem

func (rq probeQueue) Len() int { return len(rq) }

func (rq probeQueue) Less(i, j int) bool {
	return rq[i].probeAt.Compare(rq[j].probeAt) < 0
}

func (rq probeQueue) Swap(i, j int) {
	rq[i], rq[j] = rq[j], rq[i]
	rq[i].index = i
	rq[j].index = j
}

func (rq *probeQueue) Push(x any) {
	n := len(*rq)
	item := x.(*probeItem)
	item.index = n
	*rq = append(*rq, item)
}

func (rq *probeQueue) Pop() any {
	old := *rq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // don't stop the GC from reclaiming the item eventually
	item.index = -1 // for safety
	*rq = old[0 : n-1]
	return item
}

func pickFrontend(hc *healthCheck) loadbalancer.L3n4Addr {
	for _, fe := range hc.Frontends {
		// match ip family
		if hc.Backend.IsIPv6() == fe.IsIPv6() {
			return fe
		}
	}
	return loadbalancer.L3n4Addr{}
}

func probeFunc(log *slog.Logger, db *statedb.DB, healthChecks statedb.RWTable[*healthCheck], ctx context.Context, item *probeItem) func() error {
	return func() error {
		hc := item.hc.clone()
		result := probe(probeParams{
			ctx:     ctx,
			logger:  log,
			config:  hc.Config,
			svcAddr: pickFrontend(hc),
			beAddr:  hc.Backend,
		})
		hc.Message = result.message
		if result.healthy {
			hc.HealthyProbeStreak++
			hc.UnhealthyProbeStreak = 0
		} else {
			hc.HealthyProbeStreak = 0
			hc.UnhealthyProbeStreak++
		}

		switch {
		case !hc.Healthy && hc.HealthyProbeStreak >= hc.Config.ThresholdHealthy:
			hc.Healthy = true
		case hc.Healthy && hc.UnhealthyProbeStreak >= hc.Config.ThresholdUnhealthy:
			hc.Healthy = false
		}
		hc.ProbedAt = time.Now()

		// Commit the probe result. While it is more expensive to do a write transaction for
		// only a single item it is important here that we report the health change quickly.
		wtxn := db.WriteTxn(healthChecks)
		// Do a CAS to update the results. If [HealthCheck] has changed in the meanwhile
		// we silently ignore the probe result and re-probe.
		healthChecks.CompareAndSwap(wtxn, item.rev, hc)
		wtxn.Commit()

		return nil
	}
}
