// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package config

//go:generate go tool dpgen config --kind enterprise --name BPFLXCEnterprise --out enterprise_lxc_config.go ../../../bpf/bpf_lxc.o
//go:generate go tool dpgen config --kind enterprise --name BPFHostEnterprise --out enterprise_host_config.go ../../../bpf/bpf_host.o
//go:generate go tool dpgen config --kind enterprise --name BPFOverlayEnterprise --out enterprise_overlay_config.go ../../../bpf/bpf_overlay.o
//go:generate go tool dpgen config --embed Node --kind object --name BPFEvpnBase --out enterprise_evpn_base_config.go ../../../bpf/enterprise_bpf_evpn.o
//go:generate go tool dpgen config --kind enterprise --name BPFEvpnEnterprise --out enterprise_evpn_config.go ../../../bpf/enterprise_bpf_evpn.o
//go:generate go tool dpgen config --kind enterprise --name BPFWireguardEnterprise --out enterprise_wireguard_config.go ../../../bpf/bpf_wireguard.o
