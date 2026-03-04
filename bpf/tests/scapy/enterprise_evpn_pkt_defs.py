# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

import pkt_defs as pd
from pkt_defs_common import *

## EVPN (enterprise_tc_evpn_*_tests.c)
evpn_icmp_req = (
    Ether(dst=pd.mac_one, src=pd.mac_two) /
    IP(src=pd.v4_ext_one, dst=pd.v4_ext_two) /
    ICMP(type="echo-request", id=1, seq=1) /
    Raw(load=b"ping")
)

evpn_icmp_req_bad_dmac = (
    Ether(dst=pd.mac_three, src=pd.mac_two) /
    IP(src=pd.v4_ext_one, dst=pd.v4_ext_two) /
    ICMP(type="echo-request", id=1, seq=1) /
    Raw(load=b"ping")
)

evpn_icmpv6_req = (
        Ether(dst=pd.mac_one, src=pd.mac_two) /
        IPv6(src=pd.v6_ext_node_one, dst=pd.v6_svc_one) /
        ICMPv6EchoRequest(id=1, seq=1) /
        Raw(load=b"ping")
)
