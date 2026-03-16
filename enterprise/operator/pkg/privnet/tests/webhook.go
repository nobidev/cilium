// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tests

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/stretchr/testify/require"

	whcfg "github.com/cilium/cilium/enterprise/operator/pkg/privnet/webhook/config"
)

func WebhookTestCell(t testing.TB) cell.Cell {
	return cell.Group(
		cell.Provide(
			func() *webhook {
				return &webhook{
					path: t.TempDir(),
					root: x509.NewCertPool(),
				}
			},
		),

		cell.Invoke(
			(*webhook).generateTLSPair,
		),

		cell.DecorateAll(
			func(cfg whcfg.Config, w *webhook) whcfg.Config {
				if !cfg.Enabled {
					return cfg
				}

				// Attempt to select a free listen port for the webhook. We cannot
				// pass a custom listener, nor let it choose a random port, hence
				// we need to hope that the port is still free once we need it.
				listener, err := net.Listen("tcp", "localhost:0")
				require.NoError(t, err, "net.Listen")
				defer listener.Close()

				cfg.HostPort = listener.Addr().String()
				cfg.TLSKeyFile, cfg.TLSCertFile = w.tlsKeyFile(), w.tlsCertFile()

				return cfg
			},
		),
	)
}

type webhook struct {
	path string
	root *x509.CertPool
}

func (w *webhook) tlsKeyFile() string  { return path.Join(w.path, "tls.key") }
func (w *webhook) tlsCertFile() string { return path.Join(w.path, "tls.crt") }

func (w *webhook) generateTLSPair(cfg whcfg.Config) error {
	if !cfg.Enabled {
		return nil
	}

	newPair := func(tmpl, parent *x509.Certificate, signer ed25519.PrivateKey) (ed25519.PrivateKey, []byte, error) {
		var reader = rand.Reader

		tmpl.NotBefore = time.Now().Add(-time.Minute)
		tmpl.NotAfter = time.Now().Add(60 * time.Minute)

		pub, priv, err := ed25519.GenerateKey(reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generating key: %w", err)
		}

		if parent == nil {
			parent, signer = tmpl, priv
		}

		der, err := x509.CreateCertificate(reader, tmpl, parent, pub, signer)
		if err != nil {
			return nil, nil, fmt.Errorf("creating certificate: %w", err)
		}

		return priv, der, nil
	}

	cakey, cader, err := newPair(&x509.Certificate{
		Subject:               pkix.Name{Organization: []string{"Cilium Test CA"}},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}, nil, nil)
	if err != nil {
		return fmt.Errorf("CA cert: %w", err)
	}

	cacrt, err := x509.ParseCertificate(cader)
	if err != nil {
		return fmt.Errorf("parsing certificate: %w", err)
	}
	w.root.AddCert(cacrt)

	key, der, err := newPair(&x509.Certificate{
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}, cacrt, cakey)
	if err != nil {
		return fmt.Errorf("server cert: %w", err)
	}

	keyder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling key: %w", err)
	}

	if err = os.WriteFile(w.tlsKeyFile(), pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: keyder},
	), 0644); err != nil {
		return fmt.Errorf("writing tls.key: %w", err)
	}

	if err = os.WriteFile(w.tlsCertFile(), pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: der},
	), 0644); err != nil {
		return fmt.Errorf("writing tls.crt: %w", err)
	}

	return nil
}
