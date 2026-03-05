// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>

#include "common.h"
#include "pktgen.h"
#include <lib/eth.h>
#include <lib/ipv6_core.h>
#include <lib/enterprise_evpn.h>
#include "enterprise_evpn_common.h"

CHECK("tc", "evpn_fib_lookup")
int evpn_fib_lookup_check(struct __ctx_buff __maybe_unused *ctx)

{
	union v6addr v6_addr_lpm_120 = EVPN_V6_ADDR0;
	union v6addr v6_addr_lpm_112 = EVPN_V6_ADDR1;
	union v6addr v6_addr_default = EVPN_V6_ADDR2;
	const struct evpn_fib_val *val;

	test_init();

	evpn_setup_fib();

	TEST("evpn_fib_lookup4 LPM 0", {
		val = evpn_fib_lookup4(1, EVPN_V4_ADDR0);
		if (!val)
			test_fatal("Failed to lookup address");

		if (val->vni != 100)
			test_error("Expected vni=100, got %d.", val->vni);
	});

	TEST("evpn_fib_lookup4 LPM 1", {
		val = evpn_fib_lookup4(1, EVPN_V4_ADDR1);
		if (!val)
			test_fatal("Failed to lookup address");

		if (val->vni != 200)
			test_error("Expected vni=200, got %d.", val->vni);
	});

	TEST("evpn_fib_lookup4 LPM default route", {
		val = evpn_fib_lookup4(1, EVPN_V4_ADDR2);
		if (!val)
			test_fatal("Failed to lookup address");

		if (val->vni != 300)
			test_error("Expected vni=300, got %d.", val->vni);
	});

	TEST("evpn_fib_lookup4 no matching", {
		val = evpn_fib_lookup4(2, EVPN_V4_ADDR0); /* 10.0.1.1, but different net_id */
		if (val)
			test_fatal("Expected no matching entry, got vni=%d.", val->vni);
	});

	TEST("evpn_fib_lookup6 LPM 0", {
		val = evpn_fib_lookup6(1, &v6_addr_lpm_120);
		if (!val)
			test_fatal("Failed to lookup address");

		if (val->vni != 100)
			test_error("Expected vni=100, got %d.", val->vni);
	});

	TEST("evpn_fib_lookup6 LPM 1", {
		val = evpn_fib_lookup6(1, &v6_addr_lpm_112);
		if (!val)
			test_fatal("Failed to lookup address");

		if (val->vni != 200)
			test_error("Expected vni=200, got %d.", val->vni);
	});

	TEST("evpn_fib_lookup6 LPM default route", {
		val = evpn_fib_lookup6(1, &v6_addr_default);
		if (!val)
			test_fatal("Failed to lookup address");

		if (val->vni != 300)
			test_error("Expected vni=300, got %d.", val->vni);
	});

	TEST("evpn_fib_lookup6 no matching", {
		val = evpn_fib_lookup6(2, &v6_addr_lpm_120); /* fd00::0101, but different net_id */
		if (val)
			test_fatal("Expected no matching entry, got vni=%d.", val->vni);
	});

	evpn_cleanup_fib();

	test_finish();
}
