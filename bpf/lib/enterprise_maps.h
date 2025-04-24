/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#ifdef LB_FLOW_LOGS_ENABLED
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, CILIUM_LB_FLOW_LOG_RB_MAP_SIZE);
       __uint(pinning, LIBBPF_PIN_BY_NAME);
} CILIUM_LB_FLOW_LOG_RB_V4_MAP __section_maps_btf;
#endif /* LB_FLOW_LOGS_ENABLED */
