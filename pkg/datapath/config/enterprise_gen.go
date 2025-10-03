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

//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/bpf_lxc.o -kind enterprise -name BPFLXCEnterprise -out enterprise_lxc_config.go
//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/bpf_host.o -kind enterprise -name BPFHostEnterprise -out enterprise_host_config.go
//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/bpf_overlay.o -kind enterprise -name BPFOverlayEnterprise -out enterprise_overlay_config.go
//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/enterprise_bpf_evpn.o -embed Node -kind object -name BPFEvpnBase -out enterprise_evpn_base_config.go
//go:generate go run github.com/cilium/cilium/tools/dpgen -path ../../../bpf/enterprise_bpf_evpn.o -kind enterprise -name BPFEvpnEnterprise -out enterprise_evpn_config.go
