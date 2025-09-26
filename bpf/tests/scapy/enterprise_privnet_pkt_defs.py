# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

import pkt_defs as pd
from scapy.all import *

# IPv4 privnet addresses for pods in the cluster, reusing svc addresses.
v4_pod_one_netip    = pd.v4_svc_one
v4_pod_two_netip    = pd.v4_svc_two

v6_pod_one_netip    = pd.v6_svc_one
ns_pod_one_maddr    = pd.l2_announce6_ns_ma # reusing same ns as pkt_defs.py which is for v6_svc_one
ns_pod_one_mmac     = pd.l2_announce6_ns_mmac

# LXC NS and NA addressing
ns_target_ip = "fe80::100"
ns_mac = "33:33:00:00:01:00" # Multicast MAC for target IP fe80::100
ns_dst_ip = "ff02::1:ff00:100" # Multicast destination for NS

# Test packet/buffer definitions
## Privnet packet definitions
privnet_net_ip_arp_req = (Ether(dst=pd.mac_bcast, src=pd.mac_one)/
                          ARP(op="who-has", psrc=v4_pod_one_netip, pdst=v4_pod_two_netip,
                              hwsrc=pd.mac_one, hwdst=pd.mac_bcast))

privnet_net_ip_arp_res = (Ether(dst=pd.mac_one, src=pd.mac_two)/
                          ARP(op="is-at", psrc=v4_pod_two_netip, pdst=v4_pod_one_netip,
                              hwsrc=pd.mac_two, hwdst=pd.mac_one))

privnet_net_ip_icmp_req = (Ether(src=pd.mac_one, dst=pd.mac_two)/
                           IP(src=v4_pod_one_netip, dst=v4_pod_two_netip)/
                           ICMP(type="echo-request", id=1, seq=1)/
                           Raw(load=b"ping"))

privnet_pod_ip_icmp_req = (Ether(src=pd.mac_one, dst=pd.mac_two)/
                           IP(src=pd.v4_pod_one, dst=pd.v4_pod_two)/
                           ICMP(type="echo-request", id=1, seq=1)/
                           Raw(load=b"ping"))

privnet_net_ip_tcp_syn = (Ether(src=pd.mac_one, dst=pd.mac_two)/
                          IP(src=v4_pod_one_netip, dst=v4_pod_two_netip)/
                          TCP(sport=1234, dport=80, flags="S")/
                          Raw(load=b"syn"))

privnet_pod_ip_tcp_syn = (Ether(src=pd.mac_one, dst=pd.mac_two)/
                          IP(src=pd.v4_pod_one, dst=pd.v4_pod_two)/
                          TCP(sport=1234, dport=80, flags="S")/
                          Raw(load=b"syn"))

## Unknown flow packet, source is translated whereas destination is not.
privnet_unknown_flow_icmp_req = (Ether(src=pd.mac_one, dst=pd.mac_two)/
                                 IP(src=pd.v4_pod_one, dst=v4_pod_two_netip)/
                                 ICMP(type="echo-request", id=1, seq=1)/
                                 Raw(load=b"ping"))

## IPv6 NS and NA packets

### Packets coming from LXC
privnet_lxc_ns = (Ether(src=pd.mac_one, dst=ns_mac)/
                  IPv6(src=v6_pod_one_netip, dst=ns_dst_ip, hlim=255)/
                  ICMPv6ND_NS(tgt=ns_target_ip)/
                  ICMPv6NDOptSrcLLAddr(lladdr=pd.mac_one))

privnet_lxc_na = (Ether(src=pd.mac_two, dst=pd.mac_one)/
                  IPv6(src=ns_target_ip, dst=v6_pod_one_netip, hlim=255)/
                  ICMPv6ND_NA(R=0, S=1, O=1, tgt=ns_target_ip)/
                  ICMPv6NDOptDstLLAddr(lladdr=pd.mac_two))

### Packets coming to netdev
privnet_netdev_ns = (Ether(src=pd.mac_one, dst=ns_pod_one_mmac)/
                     IPv6(src=pd.v6_ext_node_one, dst=ns_pod_one_maddr, hlim=255)/
                     ICMPv6ND_NS(tgt=v6_pod_one_netip)/
                     ICMPv6NDOptSrcLLAddr(lladdr=pd.mac_one))

privnet_netdev_na = (Ether(src=pd.mac_two, dst=pd.mac_one)/
                     IPv6(src=v6_pod_one_netip, dst=pd.v6_ext_node_one, hlim=255)/
                     ICMPv6ND_NA(R=0, S=1, O=1, tgt=v6_pod_one_netip)/
                     ICMPv6NDOptDstLLAddr(lladdr=pd.mac_two))
