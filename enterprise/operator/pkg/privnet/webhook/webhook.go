// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package webhook

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/webhook/config"
)

// Handler describes a handler to be registered into the private networks webhook.
type Handler struct {
	Path    string
	Handler admission.Handler
}

// HandlersOut is a utility struct for providing a list of [Handlers] to the hive.
type HandlersOut struct {
	cell.Out

	Handlers []Handler `group:"privnet-webhook-handlers,flatten"`
}

func register(in struct {
	cell.In

	JobGroup job.Group
	Config   config.Config

	Handlers []Handler `group:"privnet-webhook-handlers"`
}) error {
	if !in.Config.Enabled || len(in.Handlers) == 0 {
		return nil
	}

	host, sport, err := net.SplitHostPort(in.Config.HostPort)
	if err != nil {
		return fmt.Errorf("parsing webhook host and port: %w", err)
	}

	port, err := strconv.ParseUint(sport, 10, 16)
	if err != nil {
		return fmt.Errorf("parsing webhook host and port: %w", err)
	}

	var getCertificateFn func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	srv := webhook.NewServer(webhook.Options{
		Host: host,
		Port: int(port),

		// Manually configure the [GetCertificate] function, because we want to
		// directly specify the full key and certificate paths, rather than base
		// directory and key/certificate names. However, we cannot initialize the
		// certificate watcher yet, because the files are not guaranteed to exist.
		TLSOpts: []func(*tls.Config){
			func(c *tls.Config) { c.GetCertificate = getCertificateFn },
		},
	})

	for _, handler := range in.Handlers {
		srv.Register(handler.Path, &admission.Webhook{Handler: handler.Handler})
	}

	in.JobGroup.Add(
		job.OneShot("run", func(ctx context.Context, health cell.Health) error {
			// [certwatcher.New] server expects that the TLS key and certificate
			// already exist when invoked, which may not be the case in this
			// context, given that we cannot block the operator bootstrap on
			// certificate generation. Hence, we manually check for their presence
			// before calling it, which also allows for better error reporting.
			var errcnt uint
			check := func(name, path string) error {
				msg := fmt.Sprintf("Waiting for TLS %s", name)
				return wait.PollUntilContextCancel(ctx, time.Second, true, /* immediate */
					func(ctx context.Context) (done bool, err error) {
						errcnt++

						fi, err := os.Stat(path)
						switch {
						// Mark the module as degraded only after that we waited
						// for a while for the target file to appear.
						case errors.Is(err, os.ErrNotExist) && errcnt < 60:
							health.OK(msg)
							return false, nil
						case err != nil:
							health.Degraded(msg, err)
							return false, nil
						case fi.IsDir():
							health.Degraded(msg, errors.New("is a directory"))
							return false, nil
						default:
							return true, nil
						}
					},
				)
			}

			if err := errors.Join(
				check("certificate", in.Config.TLSCertFile),
				check("key", in.Config.TLSKeyFile),
			); err != nil {
				return err
			}

			health.OK("Loading TLS certificate and key")
			watcher, err := certwatcher.New(in.Config.TLSCertFile, in.Config.TLSKeyFile)
			if err != nil {
				return fmt.Errorf("initializing the cert watcher: %w", err)
			}

			in.JobGroup.Add(
				job.OneShot("cert-watcher", func(ctx context.Context, _ cell.Health) error {
					return watcher.Start(ctx)
				}),
			)

			health.OK("Running")
			getCertificateFn = watcher.GetCertificate
			return srv.Start(ctx)
		}),
	)

	return nil
}
