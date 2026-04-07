// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package testutils

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/time"
)

type TLSConfig struct {
	Dir string

	CACommonName string

	ServerCommonName string
	ServerDNSNames   []string
	ServerIPAddrs    []net.IP

	WithClientCert   bool
	ClientCommonName string
	ClientDNSNames   []string

	ServerCertFileName string
	ServerKeyFileName  string
	ClientCertFileName string
	ClientKeyFileName  string
	CAFileName         string
}

type TLSFiles struct {
	ServerCertFile string
	ServerKeyFile  string
	ClientCertFile string
	ClientKeyFile  string
	CAFile         string
}

func WriteTLSFiles(t testing.TB, cfg TLSConfig) (TLSFiles, *x509.CertPool) {
	t.Helper()

	dir := cfg.Dir
	if dir == "" {
		dir = t.TempDir()
	}

	caCommonName := cfg.CACommonName
	if caCommonName == "" {
		caCommonName = "privnet-test-ca"
	}

	serverCommonName := cfg.ServerCommonName
	if serverCommonName == "" {
		serverCommonName = cmp.Or(cmp.Or(cfg.ServerDNSNames...), "localhost")
	}

	clientCommonName := cfg.ClientCommonName
	if clientCommonName == "" {
		clientCommonName = cmp.Or(cmp.Or(cfg.ClientDNSNames...), "privnet-test-client")
	}

	files := TLSFiles{
		ServerCertFile: filepath.Join(dir, cmp.Or(cfg.ServerCertFileName, "server.crt")),
		ServerKeyFile:  filepath.Join(dir, cmp.Or(cfg.ServerKeyFileName, "server.key")),
		ClientCertFile: filepath.Join(dir, cmp.Or(cfg.ClientCertFileName, "client.crt")),
		ClientKeyFile:  filepath.Join(dir, cmp.Or(cfg.ClientKeyFileName, "client.key")),
		CAFile:         filepath.Join(dir, cmp.Or(cfg.CAFileName, "ca.crt")),
	}

	caCertPEM, caKey, caCert := newCertificateAuthority(t, caCommonName)
	serverCertPEM, serverKeyPEM := newLeafCertificate(t, leafCertificateConfig{
		CA:         caCert,
		CAKey:      caKey,
		CommonName: serverCommonName,
		DNSNames:   cfg.ServerDNSNames,
		IPAddrs:    cfg.ServerIPAddrs,
		Usage:      x509.ExtKeyUsageServerAuth,
	})

	require.NoError(t, os.WriteFile(files.ServerCertFile, serverCertPEM, 0o600))
	require.NoError(t, os.WriteFile(files.ServerKeyFile, serverKeyPEM, 0o600))
	require.NoError(t, os.WriteFile(files.CAFile, caCertPEM, 0o600))

	if cfg.WithClientCert {
		clientCertPEM, clientKeyPEM := newLeafCertificate(t, leafCertificateConfig{
			CA:         caCert,
			CAKey:      caKey,
			CommonName: clientCommonName,
			DNSNames:   cfg.ClientDNSNames,
			Usage:      x509.ExtKeyUsageClientAuth,
		})
		require.NoError(t, os.WriteFile(files.ClientCertFile, clientCertPEM, 0o600))
		require.NoError(t, os.WriteFile(files.ClientKeyFile, clientKeyPEM, 0o600))
	}

	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caCertPEM))

	return files, caPool
}

type leafCertificateConfig struct {
	CA         *x509.Certificate
	CAKey      *rsa.PrivateKey
	CommonName string
	DNSNames   []string
	IPAddrs    []net.IP
	Usage      x509.ExtKeyUsage
}

func newCertificateAuthority(t testing.TB, commonName string) ([]byte, *rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	var certPEM bytes.Buffer
	require.NoError(t, pem.Encode(&certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))

	return certPEM.Bytes(), key, cert
}

func newLeafCertificate(t testing.TB, cfg leafCertificateConfig) ([]byte, []byte) {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: cfg.CommonName,
		},
		DNSNames:    cfg.DNSNames,
		IPAddresses: cfg.IPAddrs,
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{cfg.Usage},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certDER, err := x509.CreateCertificate(rand.Reader, template, cfg.CA, &key.PublicKey, cfg.CAKey)
	require.NoError(t, err)

	var certPEM bytes.Buffer
	require.NoError(t, pem.Encode(&certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))

	var keyPEM bytes.Buffer
	require.NoError(t, pem.Encode(&keyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))

	return certPEM.Bytes(), keyPEM.Bytes()
}
