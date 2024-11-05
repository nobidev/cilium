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
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

type jwtProvider struct {
	name string
	priv jwk.Key
	pub  jwk.Key
	jwks []byte
}

// newJWTProvider creates a jwtProvider object. It generates a key pair and
// JWKS that can be used for signing JWT later.
func newJWTProvider(name string) (*jwtProvider, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ED25519 key: %w", err)
	}

	jwkPriv, err := jwk.FromRaw(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK private key: %w", err)
	}

	jwkPub, err := jwk.FromRaw(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK public key: %w", err)
	}

	// Create JWKS
	jwks := jwk.NewSet()

	// Assign key ID
	jwks.Set(jwk.KeyIDKey, name+"0")

	// Add key to the JWKS
	if err := jwks.AddKey(jwkPub); err != nil {
		return nil, fmt.Errorf("failed to add key to JWKS: %w", err)
	}

	// Serialize JWKS
	jwksJSON, err := json.Marshal(jwks)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize JWKS: %w", err)
	}

	return &jwtProvider{
		name: name,
		priv: jwkPriv,
		pub:  jwkPub,
		jwks: jwksJSON,
	}, nil
}

func (p *jwtProvider) Issue(issuer string, audiences []string) ([]byte, error) {
	token, err := jwt.NewBuilder().Issuer(issuer).Audience(audiences).IssuedAt(time.Now()).Build()
	if err != nil {
		return nil, err
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA, p.priv))
	if err != nil {
		return nil, err
	}

	return signed, nil
}

func (p *jwtProvider) JWKS() []byte {
	return p.jwks
}

func TestJWTAuth(t *testing.T) {
	for _, proto := range []string{"http", "https"} {
		t.Run(strings.ToUpper(proto), func(t *testing.T) {
			ctx := context.Background()
			testName := "jwt-auth-" + proto
			testK8sNamespace := "default"
			hostName := "jwt.acme.io"
			issuer := "test@jwt.acme.io"
			audiences := []string{"audience0@jwt.acme.io", "audience1@jwt.acme.io"}

			ciliumCli, k8sCli := newCiliumAndK8sCli(t)
			dockerCli := newDockerCli(t)

			scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

			if proto == "https" {
				t.Log("Creating cert and secret...")
				scenario.createLBServerCertificate(ctx, testName, hostName)
			}

			t.Log("Creating backend apps...")
			backend := scenario.addBackendApplications(ctx, 1, backendApplicationConfig{h2cEnabled: true})[0]

			t.Log("Creating clients and add BGP peering ...")

			var client *frrContainer
			if proto == "http" {
				client = scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]
			} else {
				client = scenario.addFRRClients(ctx, 1, frrClientConfig{trustedCertsHostnames: []string{hostName}})[0]
			}

			t.Logf("Creating LB VIP resources...")
			vip := lbVIP(testK8sNamespace, testName)
			scenario.createLBVIP(ctx, vip)

			t.Logf("Creating LB BackendPool resources...")
			scenario.createLBBackendPool(ctx, lbBackendPool(testK8sNamespace, testName, withIPBackend(backend.ip, backend.port)))

			t.Log("Creating JWT auth secret...")

			provider0, err := newJWTProvider("provider0")
			if err != nil {
				t.Fatal(err)
			}

			validToken, err := provider0.Issue(issuer, audiences)
			if err != nil {
				t.Fatal(err)
			}

			provider1, err := newJWTProvider("provider1")
			if err != nil {
				t.Fatal(err)
			}

			invalidToken, err := provider1.Issue(issuer, audiences)
			if err != nil {
				t.Fatal(err)
			}

			secretName := scenario.createJWTAuthSecret(ctx, provider0.JWKS())

			t.Logf("Creating LB Service resources...")

			var service *isovalentv1alpha1.LBService
			if proto == "http" {
				// HTTP
				service = lbService(testK8sNamespace, testName, withHTTPProxyApplication(
					// Enable application-wide jwt auth
					withHttpJWTAuth(withJWTProvider("provider0", secretName)),
					// Set per-route exception
					withHttpRoute(testName,
						withHttpPath("/no-auth"),
						withHttpRouteJWTAuth(true),
					),
					// Default route
					withHttpRoute(testName),
				))
			} else {
				// HTTPS
				service = lbService(testK8sNamespace, testName,
					withPort(443),
					// Enable application-wide jwt auth
					withHTTPSProxyApplication(
						// Enable application-wide jwt auth
						withHttpsJWTAuth(withJWTProvider("provider0", secretName)),
						// Set per-route exception
						withHttpsRoute(testName,
							withHttpPath("/no-auth"),
							withHttpRouteJWTAuth(true),
						),
						// Default route
						withHttpsRoute(testName),
						withCertificate(testName),
					),
				)
			}

			scenario.createLBService(ctx, service)

			t.Logf("Waiting for full VIP connectivity of %q...", testName)
			vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

			var curlOpt string
			if proto == "http" {
				curlOpt = fmt.Sprintf("--resolve %s:80:%s", hostName, vipIP)
			} else {
				curlOpt = fmt.Sprintf("--cacert /tmp/%s.crt --resolve %s:443:%s", hostName, hostName, vipIP)
			}

			t.Run("ValidToken", func(t *testing.T) {
				cmd := curlCmd(fmt.Sprintf("-m 1 %s --oauth2-bearer %s %s://%s/needs-auth", curlOpt, string(validToken), proto, hostName))
				stdout, stderr, err := client.Exec(ctx, cmd)
				if err != nil {
					t.Fatalf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
				}
			})

			t.Run("NoToken", func(t *testing.T) {
				stdout, stderr, err := client.Exec(ctx, curlCmd(fmt.Sprintf("-m 1 %s -w '%%{response_code}' %s://%s/needs-auth", curlOpt, proto, hostName)))
				if err == nil {
					t.Fatalf("unauthenticated access succeeded\nstdout: %q\nstderr: %q", stdout, stderr)
				}
				if stdout != "401" {
					t.Fatalf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
				}
			})

			t.Run("InvalidToken", func(t *testing.T) {
				stdout, stderr, err := client.Exec(ctx, curlCmd(fmt.Sprintf("-m 1 %s -w '%%{response_code}' --oauth2-bearer %s %s://%s/needs-auth", curlOpt, string(invalidToken), proto, hostName)))
				if err == nil {
					t.Fatalf("unauthenticated access succeeded\nstdout: %q\nstderr: %q", stdout, stderr)
				}
				if stdout != "401" {
					t.Fatalf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
				}
			})

			t.Run("PerRouteException", func(t *testing.T) {
				// Ensure the per-route exception is working
				stdout, stderr, err := client.Exec(ctx, curlCmd(fmt.Sprintf("-m 1 %s %s://%s/no-auth", curlOpt, proto, hostName)))
				if err != nil {
					t.Fatalf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
				}
			})
		})
	}
}
