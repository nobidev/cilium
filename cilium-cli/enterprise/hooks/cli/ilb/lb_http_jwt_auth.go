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
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"k8s.io/utils/ptr"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/versioncheck"
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

func (p *jwtProvider) Issue(t T, issuer string, audiences []string, claims map[string]string) []byte {
	tokenBuilder := jwt.NewBuilder().Issuer(issuer).Audience(audiences).IssuedAt(time.Now())

	for k, v := range claims {
		tokenBuilder.Claim(k, v)
	}

	token, err := tokenBuilder.Build()
	if err != nil {
		t.Failedf("Failed to build token: %v", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA, p.priv))
	if err != nil {
		t.Failedf("Failed to sign token: %v", err)
	}

	return signed
}

func (p *jwtProvider) Name() string {
	return p.name
}

func (p *jwtProvider) JWKS() []byte {
	return p.jwks
}

func TestHTTPJWTAuth(t T) {
	testJWTAuth(t, "http")
}

func TestHTTPSJWTAuth(t T) {
	testJWTAuth(t, "https")
}

func testJWTAuth(t T, proto string) {
	testName := "jwt-auth-" + proto
	hostName := "jwt.acme.io"
	validIssuer := "valid-issuer@jwt.acme.io"
	validAudiences := []string{"valid-audiences@jwt.acme.io"}
	invalidIssuer := "invalid-issuer@jwt.acme.io"
	invalidAudiences := []string{"invalid-audiences@jwt.acme.io"}

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	versionSupportsJWTBasedRequestFiltering := false

	minVersion := ">=1.18.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if versioncheck.MustCompile(minVersion)(currentVersion) {
		versionSupportsJWTBasedRequestFiltering = true
	} else {
		fmt.Printf("skipping JWT based request filtering due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
	}

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	if proto == "https" {
		t.Log("Creating cert and secret...")
		scenario.createLBServerCertificate(testName, hostName)
	}

	t.Log("Creating backend apps...")
	backend := scenario.addBackendApplications(1, backendApplicationConfig{h2cEnabled: true})[0]

	t.Log("Creating clients and add BGP peering ...")

	var client *frrContainer
	if proto == "http" {
		client = scenario.addFRRClients(1, frrClientConfig{})[0]
	} else {
		client = scenario.addFRRClients(1, frrClientConfig{trustedCertsHostnames: []string{hostName}})[0]
	}

	t.Log("Creating LB VIP resources...")
	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")
	scenario.createLBBackendPool(lbBackendPool(testName, withIPBackend(backend.ip, backend.port)))

	t.Log("Creating Nginx to serve remote provider's JWKS")
	nginx := scenario.addNginx()

	t.Log("Creating JWT auth secret...")

	validProvider0, err := newJWTProvider("valid-provider0")
	if err != nil {
		t.Failedf("%s", err)
	}
	validProvider0Secret := scenario.createJWKSSecret(validProvider0.Name(), validProvider0.JWKS())

	validProvider1, err := newJWTProvider("valid-provider1")
	if err != nil {
		t.Failedf("%s", err)
	}
	validProvider1Secret := scenario.createJWKSSecret(validProvider1.Name(), validProvider1.JWKS())

	validProvider2, err := newJWTProvider("valid-provider2")
	if err != nil {
		t.Failedf("%s", err)
	}
	validProvider2Secret := scenario.createJWKSSecret(validProvider2.Name(), validProvider2.JWKS())

	invalidProvider, err := newJWTProvider("invalid-provider")
	if err != nil {
		t.Failedf("%s", err)
	}

	// An issuer that serves JWKS with remote server
	remoteProvider0, err := newJWTProvider("remote-provider0")
	if err != nil {
		t.Failedf("%s", err)
	}

	// URI of the JWKS of the provider. Use HTTP as we
	// cannot provide custom CA certificate and use IP
	// address as a host name as we cannot provide custom
	// DNS resolver.
	remoteProvider0URI := fmt.Sprintf("http://%s/remote-provider0.jwks", nginx.IP())

	// Serve JWKS with Nginx container
	if err := nginx.UploadContent(t.Context(), remoteProvider0.JWKS(), "remote-provider0.jwks"); err != nil {
		t.Failedf("%s", err)
	}

	t.Log("Creating LB Service resources...")

	var service *isovalentv1alpha1.LBService
	if proto == "http" {
		// JWT claim based filtering is supported only in Cilium v1.18.0 and later
		jwtClaimRequestFilteringRoute := func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {}

		if versionSupportsJWTBasedRequestFiltering {
			jwtClaimRequestFilteringRoute = withHttpRoute(testName,
				withHttpPath("/jwt-claim-requestfiltering"),
				withHttpRequestFilteringAllowByExactJWTClaim(map[string]string{
					"testkey": "testvalue",
				}),
			)
		}

		// HTTP
		service = lbService(testName, withHTTPProxyApplication(
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
				withHttpRouteJWTAuthDisabled(),
			),
			jwtClaimRequestFilteringRoute,
			// Default route
			withHttpRoute(testName),
		))
	} else {
		// JWT claim based filtering is supported only in Cilium v1.18.0 and later
		jwtClaimRequestFilteringRoute := func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy) {}

		if versionSupportsJWTBasedRequestFiltering {
			jwtClaimRequestFilteringRoute = withHttpsRoute(testName,
				withHttpsPath("/jwt-claim-requestfiltering"),
				withHttpsRequestFilteringAllowByExactJWTClaim(map[string]string{
					"testkey": "testvalue",
				}),
			)
		}

		// HTTPS
		service = lbService(testName,
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
					withHttpsPath("/no-auth"),
					withHttpsRouteJWTAuthDisabled(),
				),
				jwtClaimRequestFilteringRoute,
				// Default route
				withHttpsRoute(testName),
				withCertificate(testName),
			),
		)
	}

	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	var curlOpt string
	if proto == "http" {
		curlOpt = fmt.Sprintf("--resolve %s:80:%s", hostName, vipIP)
	} else {
		curlOpt = fmt.Sprintf("--cacert /tmp/%s.crt --resolve %s:443:%s", hostName, hostName, vipIP)
	}

	testsValidToken := []struct {
		name  string
		path  string
		token []byte
	}{
		{
			name:  "ValidateIssuerAndAudiences",
			path:  "/needs-auth",
			token: validProvider0.Issue(t, validIssuer, validAudiences, nil),
		},
		{
			name:  "ValidateIssuerOnly",
			path:  "/needs-auth",
			token: validProvider1.Issue(t, validIssuer, invalidAudiences, nil),
		},
		{
			name:  "ValidateAudiencesOnly",
			path:  "/needs-auth",
			token: validProvider2.Issue(t, invalidIssuer, validAudiences, nil),
		},
		{
			name:  "RemoteProvider",
			path:  "/needs-auth",
			token: remoteProvider0.Issue(t, validIssuer, validAudiences, nil),
		},
	}

	if versionSupportsJWTBasedRequestFiltering {
		testsValidToken = append(testsValidToken, struct {
			name  string
			path  string
			token []byte
		}{
			name:  "JWTClaimRequestFilteringWithClaim",
			path:  "/jwt-claim-requestfiltering",
			token: remoteProvider0.Issue(t, validIssuer, validAudiences, map[string]string{"testkey": "testvalue"}),
		})
	}

	for _, tt := range testsValidToken {
		t.Log("Checking valid token %s", tt.name)
		cmd := curlCmd(fmt.Sprintf("-m 1 %s --oauth2-bearer %s %s://%s%s", curlOpt, string(tt.token), proto, hostName, tt.path))
		t.Log("Testing %q...", cmd)
		stdout, stderr, err := client.Exec(t.Context(), cmd)
		if err != nil {
			t.Failedf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
		}
	}

	t.Log("Checking no token")
	cmd := fmt.Sprintf("-m 1 %s -w '%%{response_code}' %s://%s/needs-auth", curlOpt, proto, hostName)
	t.Log("Testing %q...", cmd)
	stdout, stderr, err := client.Exec(t.Context(), curlCmd(cmd))
	if err == nil {
		t.Failedf("unauthenticated access succeeded\nstdout: %q\nstderr: %q", stdout, stderr)
	}
	if stdout != "401" {
		t.Failedf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
	}

	testsInvalidToken := []struct {
		name  string
		path  string
		token []byte
		code  string
	}{
		{
			name:  "InvalidKey",
			path:  "/needs-auth",
			token: invalidProvider.Issue(t, validIssuer, validAudiences, nil),
			code:  "401",
		},
		{
			name:  "InvalidIssuer",
			path:  "/needs-auth",
			token: validProvider0.Issue(t, invalidIssuer, validAudiences, nil),
			code:  "401",
		},
		{
			name:  "InvalidAudience",
			path:  "/needs-auth",
			token: validProvider0.Issue(t, validIssuer, invalidAudiences, nil),
			// Envoy returns "Unauthorized" error for invalid audience (https://github.com/envoyproxy/envoy/pull/7679)
			code: "403",
		},
	}

	for _, tt := range testsInvalidToken {
		t.Log("Checking invalid token %s", tt.name)
		cmd := fmt.Sprintf("-m 1 %s -w '%%{response_code}' --oauth2-bearer %s %s://%s%s", curlOpt, string(tt.token), proto, hostName, tt.path)
		t.Log("Testing %q...", cmd)
		stdout, stderr, err := client.Exec(t.Context(), curlCmd(cmd))
		if err == nil {
			t.Failedf("unauthenticated access succeeded\nstdout: %q\nstderr: %q", stdout, stderr)
		}
		if stdout != tt.code {
			t.Failedf("unexpected error (expect: %s, got: %s): %v\nstderr: %q", tt.code, stdout, err, stderr)
		}
	}

	t.Log("Checking per-route exception")
	// Ensure the per-route exception is working
	stdout, stderr, err = client.Exec(t.Context(), curlCmd(fmt.Sprintf("-m 1 %s %s://%s/no-auth", curlOpt, proto, hostName)))
	if err != nil {
		t.Failedf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
	}
}
