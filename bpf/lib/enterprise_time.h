/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/* Monotonic clock, scalar format. */
static __always_inline __u64 bpf_ktime_get_nsec(void)
{
	return ktime_get_ns();
}

