/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include "pktgen.h"
#include <lib/eth.h>
#include <lib/ipv6_core.h>
#include "lib/enterprise_evpn.h"

#define EVPN_V4_PREFIX0 bpf_htonl(0x0a000100) /* 10.0.1.0 */
#define EVPN_V4_PREFIX1 bpf_htonl(0x0a000000) /* 10.0.0.0 */
#define EVPN_V4_PREFIX2 bpf_htonl(0x00000000) /* 0.0.0.0 */

#define EVPN_V4_ADDR0 bpf_htonl(0x0a000101) /* 10.0.1.1 */
#define EVPN_V4_ADDR1 bpf_htonl(0x0a000201) /* 10.0.2.1 */
#define EVPN_V4_ADDR2 bpf_htonl(0x0a010001) /* 10.1.0.1 */

#define EVPN_V6_PREFIX0 ((union v6addr){ .addr[0] = 0xfd, .addr[14] = 0x01 }) /* fd00::0100 */
#define EVPN_V6_PREFIX1 ((union v6addr){ .addr[0] = 0xfd }) /* fd00:: */
#define EVPN_V6_PREFIX2 ((union v6addr){}) /* :: */

#define EVPN_V6_ADDR0 ((union v6addr){ .addr[0] = 0xfd, .addr[14] = 0x01, .addr[15] = 0x01 }) /* fd00::0000:0101 */
#define EVPN_V6_ADDR1 ((union v6addr){ .addr[0] = 0xfd, .addr[14] = 0x02, .addr[15] = 0x01 }) /* fd00::0000:0201 */
#define EVPN_V6_ADDR2 ((union v6addr){ .addr[0] = 0xfd, .addr[13] = 0x01, .addr[15] = 0x01 }) /* fd00::0001:0001 */

static __always_inline void
evpn_setup_fib(void) {
	union macaddr mac0 = {.addr = mac_one_addr};
	union v6addr v6_nexthop0 = (union v6addr){ .addr = v6_node_one_addr };
	union v6addr v6_prefix_120 = EVPN_V6_PREFIX0;
	union v6addr v6_prefix_112 = EVPN_V6_PREFIX1;
	union v6addr v6_prefix_0 = EVPN_V6_PREFIX2;

	evpn_fib_v4_add_nh4(1, EVPN_V4_PREFIX0, 24, 100, mac0, v4_node_one); /* 10.0.1.0/24 */
	evpn_fib_v4_add_nh4(1, EVPN_V4_PREFIX1, 16, 200, mac0, v4_node_one); /* 10.0.0.0/16 */
	evpn_fib_v4_add_nh6(1, EVPN_V4_PREFIX2, 0, 300, mac0, &v6_nexthop0); /* 0.0.0.0/0 */
	evpn_fib_v6_add_nh6(1, &v6_prefix_120, 120, 100, mac0, &v6_nexthop0); /* fd00::0100/120 */
	evpn_fib_v6_add_nh6(1, &v6_prefix_112, 112, 200, mac0, &v6_nexthop0); /* fd00::/112 */
	evpn_fib_v6_add_nh4(1, &v6_prefix_0, 0, 300, mac0, v4_node_one); /* ::/0 */
}

static __always_inline void
evpn_cleanup_fib(void) {
	union v6addr v6_prefix_120 = EVPN_V6_PREFIX0;
	union v6addr v6_prefix_112 = EVPN_V6_PREFIX1;
	union v6addr v6_prefix_0 = EVPN_V6_PREFIX2;

	evpn_fib_v4_del(1, EVPN_V4_PREFIX0, 24);
	evpn_fib_v4_del(1, EVPN_V4_PREFIX1, 16);
	evpn_fib_v4_del(1, EVPN_V4_PREFIX2, 0);
	evpn_fib_v6_del(1, &v6_prefix_120, 120);
	evpn_fib_v6_del(1, &v6_prefix_112, 112);
	evpn_fib_v6_del(1, &v6_prefix_0, 0);
}
