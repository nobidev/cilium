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

var Tests = []func(t T){
	TestRequestedVIP,
	TestSharedVIP,
	TestBGPHealthCheck,
	TestBGPHealthCheckSubset,
	TestHTTPAndT2HealthChecks,
	TestHTTP2,
	TestHTTPPath,
	TestHTTPRoutes,
	TestHTTPClientIP,
	TestHTTPBasicAuth,
	TestHTTPJWTAuth,
	TestHTTPConnectionFiltering,
	TestHTTPProxyProtocol,
	TestHTTPRouteRatelimiting,
	TestHTTPApplicationRatelimiting,
	TestHTTPRequestFiltering,
	TestHTTPPersistentBackendWithCookie,
	TestHTTPPersistentBackendWithSourceIP,
	TestHTTPS,
	TestHTTPSRoutes,
	TestHTTPS_H2,
	TestHTTPSBasicAuth,
	TestHTTPSJWTAuth,
	TestHTTPSConnectionFiltering,
	TestHTTPSRouteRatelimiting,
	TestHTTPSApplicationRatelimiting,
	TestHTTPSRequestFiltering,
	TestDNSBackend,
	TestHeadlessService,
	TestTCPProxyT1OnlyConnectionFiltering,
	TestTCPProxyT1T2ConnectionFiltering,
	TestTCPProxyAutoConnectionFiltering,
	TestTCPProxyT1OnlyPersistentBackend,
	TestTCPProxyT1T2PersistentBackend,
	TestTCPProxyAutoPersistentBackend,
	TestTCPProxyRatelimiting,
	TestTCPProxyRatelimiting_Fail_T1Only,
	TestTCPProxy,
	TestTLSPassthrough,
	TestTLSPassthroughConnectionFiltering,
	TestTLSPassthroughRatelimiting,
	TestTLSProxyTCPBackend,
	TestTLSProxyTLSBackend,
	TestTLSProxyConnectionFiltering,
	TestTLSProxyRatelimiting,
	TestUDPProxyT1Only,
	TestUDPProxyT1T2,
	TestUDPProxyAuto,
	TestUDPProxyT1OnlyConnectionFiltering,
	TestUDPProxyT1T2ConnectionFiltering,
	TestUDPProxyAutoConnectionFiltering,
	TestUDPProxyT1OnlySession,
	TestUDPProxyT1T2Session,
	TestUDPProxyAutoSession,
	TestUDPProxyT1OnlyPersistentBackend,
	TestUDPProxyT1T2PersistentBackend,
	TestUDPProxyAutoPersistentBackend,
	TestLabelBasedBackend_T1T2,
	TestLabelBasedBackend_T1Only,
}
