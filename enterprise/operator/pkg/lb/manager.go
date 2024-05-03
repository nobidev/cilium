//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lb

import (
	"context"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/workqueue"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sclient "github.com/cilium/cilium/pkg/k8s/client"
	v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

type LBParams struct {
	cell.In

	Cfg Config

	Logger   logrus.FieldLogger
	JobGroup job.Group

	Clientset k8sclient.Clientset

	ILBResource         resource.Resource[*isovalent_api_v1alpha1.IsovalentLB]
	NodeResource        resource.Resource[*cilium_api_v2.CiliumNode]
	EnvoyConfigResource resource.Resource[*cilium_api_v2.CiliumEnvoyConfig]
}

type LBManager struct {
	cfg    Config
	logger logrus.FieldLogger

	// resource to be modified

	// resources to watch
	ilbResource  resource.Resource[*isovalent_api_v1alpha1.IsovalentLB]
	nodeResource resource.Resource[*cilium_api_v2.CiliumNode]

	nodeStore        resource.Store[*cilium_api_v2.CiliumNode]
	envoyConfigStore resource.Store[*cilium_api_v2.CiliumEnvoyConfig]

	// internal state
	ilbEvents  <-chan resource.Event[*isovalent_api_v1alpha1.IsovalentLB]
	nodeEvents <-chan resource.Event[*cilium_api_v2.CiliumNode]

	// TODO: Introduce caching for IsovalentLB objects.

	initialSynced chan struct{}
	tier2Nodes    map[string]string // node-name -> IP

	coreV1Cleint corev1.CoreV1Interface
	cecClient    v2.CiliumEnvoyConfigsGetter
}

func newLBManager(p LBParams) (*LBManager, error) {
	lbm := &LBManager{
		cfg:           p.Cfg,
		logger:        p.Logger,
		ilbResource:   p.ILBResource,
		nodeResource:  p.NodeResource,
		initialSynced: make(chan struct{}),
		tier2Nodes:    make(map[string]string),
		coreV1Cleint:  p.Clientset.CoreV1(),
		cecClient:     p.Clientset.CiliumV2(),
	}
	p.JobGroup.Add(
		job.OneShot("lb-manager-main", func(ctx context.Context, health cell.Health) error {
			lbm.Run(ctx)
			return nil
		}),

		job.OneShot("lb-manager-init-sync", func(ctx context.Context, health cell.Health) error {
			var err error
			lbm.nodeStore, err = p.NodeResource.Store(ctx)
			if err == nil {
				lbm.logger.Info("CiliumNode synced in LBManager")
			}

			lbm.envoyConfigStore, err = p.EnvoyConfigResource.Store(ctx)
			if err == nil {
				close(lbm.initialSynced)
			}

			return err
		}),
	)

	return lbm, nil
}

func (lbm *LBManager) Run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	lbm.logger.Info("Initializing")
	defer lbm.logger.Info("Shutting down")

	lbm.ilbEvents = lbm.ilbResource.Events(ctx, eventsOpts)
	lbm.nodeEvents = lbm.nodeResource.Events(ctx, eventsOpts)

	// f.resync(ctx)
	<-lbm.initialSynced

	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-lbm.ilbEvents:
			if !ok {
				lbm.logger.Info("ILB events channel closed")
				return
			}
			lbm.handleILBEvent(ctx, event)

		case event, ok := <-lbm.nodeEvents:
			if !ok {
				lbm.logger.Info("node events channel closed")
				return
			}
			lbm.handleNodeEvent(ctx, event)
		}
	}
}

var eventsOpts = resource.WithRateLimiter(
	workqueue.NewItemExponentialFailureRateLimiter(250*time.Millisecond, 5*time.Minute),
)
