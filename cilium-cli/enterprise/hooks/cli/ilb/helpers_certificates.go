//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/url"
	"time"
)

type certTemplateOpts func(*x509.Certificate)

func withCertificateSANDNSNames(dnsNames ...string) certTemplateOpts {
	return func(c *x509.Certificate) {
		c.DNSNames = append(c.DNSNames, dnsNames...)
	}
}

func withCertificateSANIPs(ips ...string) certTemplateOpts {
	return func(c *x509.Certificate) {
		for _, ip := range ips {
			c.IPAddresses = append(c.IPAddresses, net.ParseIP(ip))
		}
	}
}

func withCertificateSANMails(mails ...string) certTemplateOpts {
	return func(c *x509.Certificate) {
		c.EmailAddresses = append(c.EmailAddresses, mails...)
	}
}

func withCertificateSANURIs(uris ...string) certTemplateOpts {
	return func(c *x509.Certificate) {
		for _, uri := range uris {
			uri, err := url.Parse(uri)
			if err != nil {
				log.Fatal(err)
			}

			c.URIs = append(c.URIs, uri)
		}
	}
}

// can not be combined with other SAN types
func withCertificateSANOtherNameUPN(upn string) certTemplateOpts {
	return func(c *x509.Certificate) {
		upnExt, err := asn1.Marshal(GeneralNames{
			OtherName: OtherName{
				// init our ASN.1 object identifier
				OID: asn1.ObjectIdentifier{
					1, 3, 6, 1, 4, 1, 311, 20, 2, 3, // OID for UPN
				},
				Value: UPN{
					A: upn,
				},
			},
		})
		if err != nil {
			log.Fatal(err)
		}

		extSubjectAltName := pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 17}, // OID for SAN extension
			Critical: false,
			Value:    upnExt,
		}

		c.ExtraExtensions = append(c.ExtraExtensions, extSubjectAltName)
	}
}

func genTemplate(usage x509.KeyUsage, extUsage []x509.ExtKeyUsage, opts ...certTemplateOpts) (*x509.Certificate, error) {
	notBefore := time.Now().Add(-24 * time.Hour)
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SN: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              usage,
		ExtKeyUsage:           extUsage,
		BasicConstraintsValid: true,
	}

	for _, opt := range opts {
		opt(template)
	}

	return template, nil
}

func encodePEM(derBytes []byte, priv *rsa.PrivateKey) (*bytes.Buffer, *bytes.Buffer, error) {
	var cert, key bytes.Buffer

	if err := pem.Encode(&cert, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to PEM encode cert: %w", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal pri key: %w", err)
	}

	if err := pem.Encode(&key, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to PEM encode key: %w", err)
	}

	return &key, &cert, nil
}

func genSelfSignedX509(host string) (*bytes.Buffer, *bytes.Buffer, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate priv key: %w", err)
	}

	template, err := genTemplate(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, withCertificateSANDNSNames(host))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate template: %w", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cert: %w", err)
	}

	key, cert, err := encodePEM(derBytes, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode PEM: %w", err)
	}

	return key, cert, nil
}

// UPN type for asn1 encoding. This will hold
// our utf-8 encoded string.
type UPN struct {
	A string `asn1:"utf8"`
}

// OtherName type for asn1 encoding
type OtherName struct {
	OID   asn1.ObjectIdentifier
	Value any `asn1:"tag:0"`
}

// GeneralNames type for asn1 encoding
type GeneralNames struct {
	OtherName OtherName `asn1:"tag:0"`
}
