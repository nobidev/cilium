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
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"k8s.io/utils/ptr"

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

func (p *jwtProvider) Issue(issuer string, audiences []string) []byte {
	token, err := jwt.NewBuilder().Issuer(issuer).Audience(audiences).IssuedAt(time.Now()).Build()
	if err != nil {
		fatalf("Failed to build token: %v", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA, p.priv))
	if err != nil {
		fatalf("Failed to sign token: %v", err)
	}

	return signed
}

func (p *jwtProvider) Name() string {
	return p.name
}

func (p *jwtProvider) JWKS() []byte {
	return p.jwks
}

func TestHTTPJWTAuth() {
	testJWTAuth("http")
}

func TestHTTPSJWTAuth() {
	testJWTAuth("https")
}

func testJWTAuth(proto string) {
	ctx := context.Background()
	testName := "jwt-auth-" + proto
	testK8sNamespace := "default"
	hostName := "jwt.acme.io"
	validIssuer := "valid-issuer@jwt.acme.io"
	validAudiences := []string{"valid-audiences@jwt.acme.io"}
	invalidIssuer := "invalid-issuer@jwt.acme.io"
	invalidAudiences := []string{"invalid-audiences@jwt.acme.io"}

	ciliumCli, k8sCli := NewCiliumAndK8sCli()
	dockerCli := NewDockerCli()

	scenario := newLBTestScenario(testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	if proto == "https" {
		fmt.Println("Creating cert and secret...")
		scenario.createLBServerCertificate(ctx, testName, hostName)
	}

	fmt.Println("Creating backend apps...")
	backend := scenario.addBackendApplications(ctx, 1, backendApplicationConfig{h2cEnabled: true})[0]

	fmt.Println("Creating clients and add BGP peering ...")

	var client *frrContainer
	if proto == "http" {
		client = scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]
	} else {
		client = scenario.addFRRClients(ctx, 1, frrClientConfig{trustedCertsHostnames: []string{hostName}})[0]
	}

	fmt.Println("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(ctx, vip)

	fmt.Println("Creating LB BackendPool resources...")
	scenario.createLBBackendPool(ctx, lbBackendPool(testK8sNamespace, testName, withIPBackend(backend.ip, backend.port)))

	fmt.Println("Creating Nginx to serve remote provider's JWKS")
	nginx := scenario.addNginx(ctx)

	fmt.Println("Creating JWT auth secret...")

	validProvider0, err := newJWTProvider("valid-provider0")
	if err != nil {
		fatalf("%s", err)
	}
	validProvider0Secret := scenario.createJWKSSecret(ctx, validProvider0.Name(), validProvider0.JWKS())

	validProvider1, err := newJWTProvider("valid-provider1")
	if err != nil {
		fatalf("%s", err)
	}
	validProvider1Secret := scenario.createJWKSSecret(ctx, validProvider1.Name(), validProvider1.JWKS())

	validProvider2, err := newJWTProvider("valid-provider2")
	if err != nil {
		fatalf("%s", err)
	}
	validProvider2Secret := scenario.createJWKSSecret(ctx, validProvider2.Name(), validProvider2.JWKS())

	invalidProvider, err := newJWTProvider("invalid-provider")
	if err != nil {
		fatalf("%s", err)
	}

	// An issuer that serves JWKS with remote server
	remoteProvider0, err := newJWTProvider("remote-provider0")
	if err != nil {
		fatalf("%s", err)
	}

	// URI of the JWKS of the provider. Use HTTP as we
	// cannot provide custom CA certificate and use IP
	// address as a host name as we cannot provide custom
	// DNS resolver.
	remoteProvider0URI := fmt.Sprintf("http://%s/remote-provider0.jwks", nginx.IP())

	// Serve JWKS with Nginx container
	if err := nginx.UploadContent(ctx, remoteProvider0.JWKS(), "remote-provider0.jwks"); err != nil {
		fatalf("%s", err)
	}

	fmt.Println("Creating LB Service resources...")

	var service *isovalentv1alpha1.LBService
	if proto == "http" {
		// HTTP
		service = lbService(testK8sNamespace, testName, withHTTPProxyApplication(
			// Enable application-wide jwt auth
			withHttpJWTAuth(
				// Only matches to the validProvider0's key. Check issuer and audiences.
				withJWTProviderWithLocalJWKS(
					"valid-provider0",
					ptr.To(validIssuer),
					validAudiences,
					validProvider0Secret,
				),
				// Only matches to the validProvider1's key. Check issuer, not audiences.
				withJWTProviderWithLocalJWKS(
					"valid-provider1",
					ptr.To(validIssuer),
					[]string{},
					validProvider1Secret,
				),
				// Only matches to the validProvider2's key. Check audiences, not issuers.
				withJWTProviderWithLocalJWKS(
					"valid-provider2",
					nil,
					validAudiences,
					validProvider2Secret,
				),
				// Only matches to the remoteProvider0's key.
				withJWTProviderWithRemoteJWKS(
					"remote-provider0",
					ptr.To(validIssuer),
					validAudiences,
					remoteProvider0URI,
				),
			),
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
				withHttpsJWTAuth(
					// Only matches to the validProvider0's key. Check issuer and audiences.
					withJWTProviderWithLocalJWKS(
						"valid-provider0",
						ptr.To(validIssuer),
						validAudiences,
						validProvider0Secret,
					),
					// Only matches to the validProvider1's key. Check issuer, not audiences.
					withJWTProviderWithLocalJWKS(
						"valid-provider1",
						ptr.To(validIssuer),
						[]string{},
						validProvider1Secret,
					),
					// Only matches to the validProvider2's key. Check audiences, not issuers.
					withJWTProviderWithLocalJWKS(
						"valid-provider2",
						nil,
						validAudiences,
						validProvider2Secret,
					),
					// Only matches to the remoteProvider0's key.
					withJWTProviderWithRemoteJWKS(
						"remote-provider0",
						ptr.To(validIssuer),
						validAudiences,
						remoteProvider0URI,
					),
				),
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

	maybeSysdump(testName, "")

	fmt.Println("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	var curlOpt string
	if proto == "http" {
		curlOpt = fmt.Sprintf("--resolve %s:80:%s", hostName, vipIP)
	} else {
		curlOpt = fmt.Sprintf("--cacert /tmp/%s.crt --resolve %s:443:%s", hostName, hostName, vipIP)
	}

	testsValidToken := []struct {
		name  string
		token []byte
	}{
		{
			name:  "ValidateIssuerAndAudiences",
			token: validProvider0.Issue(validIssuer, validAudiences),
		},
		{
			name:  "ValidateIssuerOnly",
			token: validProvider1.Issue(validIssuer, invalidAudiences),
		},
		{
			name:  "ValidateAudiencesOnly",
			token: validProvider2.Issue(invalidIssuer, validAudiences),
		},
		{
			name:  "RemoteProvider",
			token: remoteProvider0.Issue(validIssuer, validAudiences),
		},
	}
	for _, tt := range testsValidToken {
		fmt.Printf("Checking valid token %s\n", tt.name)
		cmd := curlCmd(fmt.Sprintf("-m 1 %s --oauth2-bearer %s %s://%s/needs-auth", curlOpt, string(tt.token), proto, hostName))
		stdout, stderr, err := client.Exec(ctx, cmd)
		if err != nil {
			fatalf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
		}
	}

	fmt.Println("Checking no token")
	stdout, stderr, err := client.Exec(ctx, curlCmd(fmt.Sprintf("-m 1 %s -w '%%{response_code}' %s://%s/needs-auth", curlOpt, proto, hostName)))
	if err == nil {
		fatalf("unauthenticated access succeeded\nstdout: %q\nstderr: %q", stdout, stderr)
	}
	if stdout != "401" {
		fatalf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
	}

	testsInvalidToken := []struct {
		name  string
		token []byte
		code  string
	}{
		{
			name:  "InvalidKey",
			token: invalidProvider.Issue(validIssuer, validAudiences),
			code:  "401",
		},
		{
			name:  "InvalidIssuer",
			token: validProvider0.Issue(invalidIssuer, validAudiences),
			code:  "401",
		},
		{
			name:  "InvalidAudience",
			token: validProvider0.Issue(validIssuer, invalidAudiences),
			// Envoy returns "Unauthorized" error for invalid audience (https://github.com/envoyproxy/envoy/pull/7679)
			code: "403",
		},
	}

	for _, tt := range testsInvalidToken {
		fmt.Printf("Checking invalid token %s\n", tt.name)
		stdout, stderr, err := client.Exec(ctx, curlCmd(
			fmt.Sprintf("-m 1 %s -w '%%{response_code}' --oauth2-bearer %s %s://%s/needs-auth", curlOpt, string(tt.token), proto, hostName)),
		)
		if err == nil {
			fatalf("unauthenticated access succeeded\nstdout: %q\nstderr: %q", stdout, stderr)
		}
		if stdout != tt.code {
			fatalf("unexpected error (expect: %s, got: %s): %v\nstderr: %q", tt.code, stdout, err, stderr)
		}
	}

	fmt.Println("Checking per-route exception")
	// Ensure the per-route exception is working
	stdout, stderr, err = client.Exec(ctx, curlCmd(fmt.Sprintf("-m 1 %s %s://%s/no-auth", curlOpt, proto, hostName)))
	if err != nil {
		fatalf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
	}
}
